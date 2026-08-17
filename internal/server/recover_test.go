package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// TestRecoverMiddleware_BeforeHeadersWritesJSON500 confirms a panic before
// any body bytes are written lands as a JSON 500 to the client.
func TestRecoverMiddleware_BeforeHeadersWritesJSON500(t *testing.T) {
	observability.SetCrashDumpDir(t.TempDir())

	h := recoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("handler-boom")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "HANDLER_PANIC") {
		t.Fatalf("expected error code in body, got: %s", body)
	}
}

// TestRecoverMiddleware_AfterHeadersNoDoubleWrite confirms that when a
// handler panics MID-STREAM (after writing bytes), the middleware does not
// attempt to write a 500 — doing so would corrupt the already-flushed
// response. The client gets a truncated response; the panic is still logged
// and dumped.
func TestRecoverMiddleware_AfterHeadersNoDoubleWrite(t *testing.T) {
	observability.SetCrashDumpDir(t.TempDir())

	h := recoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("partial-"))
		panic("after-headers-boom")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (already flushed), got %d", rec.Code)
	}
	// Body should contain only what was written before the panic.
	if rec.Body.String() != "partial-" {
		t.Fatalf("expected partial body preserved, got: %q", rec.Body.String())
	}
}

// TestRecoverMiddleware_HappyPathPassThrough ensures the middleware does not
// corrupt normal responses.
func TestRecoverMiddleware_HappyPathPassThrough(t *testing.T) {
	h := recoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"hello":"world"}`))
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ok", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Test"); got != "ok" {
		t.Fatalf("header lost through wrapper: %q", got)
	}
	if rec.Body.String() != `{"hello":"world"}` {
		t.Fatalf("body corrupted: %s", rec.Body.String())
	}
}

// TestRecoverMiddleware_AbortHandlerIsNotReportedAsCrash protects the
// ReverseProxy disconnect path. net/http.ErrAbortHandler is a control-flow
// sentinel consumed by the outer net/http server, not an application crash.
func TestRecoverMiddleware_AbortHandlerIsNotReportedAsCrash(t *testing.T) {
	dumpDir := t.TempDir()
	observability.SetCrashDumpDir(dumpDir)

	h := recoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/stream", nil)

	func() {
		defer func() {
			if got := recover(); got != http.ErrAbortHandler {
				t.Fatalf("expected ErrAbortHandler to reach outer net/http server, got %v", got)
			}
		}()
		h.ServeHTTP(rec, req)
	}()

	entries, err := os.ReadDir(dumpDir)
	if err != nil {
		t.Fatalf("read crash dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("ErrAbortHandler must not create a crash dump; got %v", entries)
	}
}

// TestTrackedWriter_FlusherPassThrough confirms http.Flusher type assertion
// still succeeds through the wrapper — required for SSE streaming.
func TestTrackedWriter_FlusherPassThrough(t *testing.T) {
	rec := httptest.NewRecorder()
	tw := &trackedWriter{ResponseWriter: rec}
	if _, ok := interface{}(tw).(http.Flusher); !ok {
		t.Fatal("trackedWriter must implement http.Flusher for SSE")
	}
}

type deadlineWriter struct {
	http.ResponseWriter
	deadline time.Time
}

func (w *deadlineWriter) SetReadDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

func TestTrackedWriter_ResponseControllerUnwrapsReadDeadline(t *testing.T) {
	underlying := &deadlineWriter{ResponseWriter: httptest.NewRecorder()}
	tw := &trackedWriter{ResponseWriter: underlying}
	want := time.Now().Add(time.Minute).Round(time.Millisecond)
	if err := http.NewResponseController(tw).SetReadDeadline(want); err != nil {
		t.Fatalf("SetReadDeadline through recovery wrapper: %v", err)
	}
	if !underlying.deadline.Equal(want) {
		t.Fatalf("read deadline did not reach server writer: got=%s want=%s", underlying.deadline, want)
	}
}
