package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGroupReplayBody_BoundsAndReleasesMemory(t *testing.T) {
	budget := newGroupReplayBudget(32)
	replay, err := readGroupReplayBody(bytes.NewReader([]byte("payload")), 7, 16, budget)
	if err != nil {
		t.Fatal(err)
	}
	if got := budget.used.Load(); got != 7 {
		t.Fatalf("reserved=%d, want 7", got)
	}
	for attempt := 0; attempt < 2; attempt++ {
		r := replay.Open()
		got, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil || string(got) != "payload" {
			t.Fatalf("attempt %d replay=%q err=%v", attempt, got, err)
		}
	}
	if got := budget.used.Load(); got != 7 {
		t.Fatalf("captured retries must retain memory, got %d", got)
	}
	replay.Commit()
	if got := budget.used.Load(); got != 0 {
		t.Fatalf("committed replay must release memory, got %d", got)
	}
}

func TestGroupReplayBody_RejectsDeclaredAndChunkedOversize(t *testing.T) {
	for _, tc := range []struct {
		name          string
		contentLength int64
	}{
		{name: "declared", contentLength: 5},
		{name: "chunked", contentLength: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget := newGroupReplayBudget(32)
			_, err := readGroupReplayBody(bytes.NewReader([]byte("12345")), tc.contentLength, 4, budget)
			if !errors.Is(err, errGroupReplayBodyTooLarge) {
				t.Fatalf("err=%v, want body-too-large", err)
			}
			if got := budget.used.Load(); got != 0 {
				t.Fatalf("rejected body leaked %d budget bytes", got)
			}
		})
	}
}

func TestGroupReplayBody_RejectsBudgetExhaustion(t *testing.T) {
	budget := newGroupReplayBudget(3)
	if _, err := readGroupReplayBody(bytes.NewReader([]byte("1234")), 4, 8, budget); !errors.Is(err, errGroupReplayCapacity) {
		t.Fatalf("err=%v, want replay-capacity", err)
	}
	if got := budget.used.Load(); got != 0 {
		t.Fatalf("capacity rejection leaked %d bytes", got)
	}
}

func TestGroupFailoverWriter_ReleasesReplayAtClientCommit(t *testing.T) {
	t.Run("success waits for transport body close", func(t *testing.T) {
		budget := newGroupReplayBudget(16)
		replay, err := readGroupReplayBody(bytes.NewReader([]byte("abc")), 3, 8, budget)
		if err != nil {
			t.Fatal(err)
		}
		reader := replay.Open()
		fw := newGroupFailoverWriter(httptest.NewRecorder(), true)
		fw.onCommit = replay.Commit
		fw.WriteHeader(http.StatusOK)
		if got := budget.used.Load(); got != 3 {
			t.Fatalf("early response released while transport reader active: %d", got)
		}
		_ = reader.Close()
		if got := budget.used.Load(); got != 0 {
			t.Fatalf("reader close after commit retained %d bytes", got)
		}
	})

	t.Run("captured error retains until final flush", func(t *testing.T) {
		budget := newGroupReplayBudget(16)
		replay, err := readGroupReplayBody(bytes.NewReader([]byte("abc")), 3, 8, budget)
		if err != nil {
			t.Fatal(err)
		}
		fw := newGroupFailoverWriter(httptest.NewRecorder(), true)
		fw.onCommit = replay.Commit
		fw.WriteHeader(http.StatusInternalServerError)
		if got := budget.used.Load(); got != 3 {
			t.Fatalf("captured error released replay before retry: %d", got)
		}
		fw.flushCaptured()
		if got := budget.used.Load(); got != 0 {
			t.Fatalf("final flush retained %d bytes", got)
		}
	})
}

func TestGroupReplayBody_ObserverReplacementDoesNotLoseOwner(t *testing.T) {
	budget := newGroupReplayBudget(16)
	replay, err := readGroupReplayBody(bytes.NewReader([]byte("abc")), 3, 8, budget)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Body = replay.Open()
	req.ContentLength = int64(replay.Len())
	ownerReader := req.Body
	if got := bufferRequestBodyForObserver(req); string(got) != "abc" {
		t.Fatalf("observer body=%q, want abc", got)
	}
	if req.Body == ownerReader {
		t.Fatal("observer helper did not replace Request.Body as expected")
	}
	replay.Commit()
	if got := budget.used.Load(); got != 3 {
		t.Fatalf("commit released while the original owner reader was open: %d", got)
	}
	_ = ownerReader.Close()
	if got := budget.used.Load(); got != 0 {
		t.Fatalf("closing the retained owner reader leaked %d budget bytes", got)
	}
}
