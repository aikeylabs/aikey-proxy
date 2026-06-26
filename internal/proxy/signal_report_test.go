package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// signal_report_test.go — covers the I5 emit path's pure + best-effort pieces.
// loop()'s 30s ticker is timing-driven and not deterministically testable, so we
// call post() directly (the loop only batches + invokes it) — see TestSignalPost*.

func TestParseUnifiedUtil5h(t *testing.T) {
	const hdr = "anthropic-ratelimit-unified-5h-utilization"
	tests := []struct {
		name   string
		set    bool
		val    string
		wantV  float64
		wantOK bool
	}{
		{"valid", true, "0.6", 0.6, true},
		{"missing", false, "", 0, false},
		{"malformed", true, "abc", 0, false},
		{"above_one", true, "1.5", 0, false},
		{"negative", true, "-0.1", 0, false},
		{"zero_ok", true, "0", 0, true},
		{"one_ok", true, "1", 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.set {
				h.Set(hdr, tt.val)
			}
			v, ok := parseUnifiedUtil5h(h)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && v != tt.wantV {
				t.Fatalf("v = %v, want %v", v, tt.wantV)
			}
		})
	}
}

func TestEnqueueNilAndEmptyAreSafe(t *testing.T) {
	// nil receiver guard: feature-off reporter must not panic.
	var nilR *signalReporter
	nilR.enqueue("c1", 100, 0.5) // must not panic

	// empty credentialID is dropped — observable via the buffered channel.
	r := &signalReporter{in: make(chan signalSample, 4)}
	r.enqueue("", 100, 0.5)
	if len(r.in) != 0 {
		t.Fatalf("empty credentialID should be dropped, buffered = %d", len(r.in))
	}
	r.enqueue("c1", 100, 0.5)
	if len(r.in) != 1 {
		t.Fatalf("valid sample should be queued, buffered = %d", len(r.in))
	}
}

func TestSignalPostSendsBatch(t *testing.T) {
	type captured struct {
		method      string
		auth        string
		contentType string
		body        []byte
	}
	got := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got <- captured{req.Method, req.Header.Get("Authorization"), req.Header.Get("Content-Type"), b}
	}))
	defer srv.Close()

	r := newSignalReporter(srv.URL, func(context.Context) (string, error) { return "tok-123", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}
	r.post([]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6}})

	c := <-got
	if c.method != http.MethodPost {
		t.Errorf("method = %q, want POST", c.method)
	}
	if c.auth != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want %q", c.auth, "Bearer tok-123")
	}
	if c.contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", c.contentType)
	}
	var decoded struct {
		Samples []signalSample `json:"samples"`
	}
	if err := json.Unmarshal(c.body, &decoded); err != nil {
		t.Fatalf("body not valid JSON: %v (raw %s)", err, c.body)
	}
	if len(decoded.Samples) != 1 || decoded.Samples[0] != (signalSample{CredentialID: "c1", TS: 100, Util5h: 0.6}) {
		t.Fatalf("decoded samples = %+v, want one {c1,100,0.6}", decoded.Samples)
	}
}

func TestSignalPostBearerErrorDoesNotPost(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	r := newSignalReporter(srv.URL, func(context.Context) (string, error) {
		return "", io.ErrUnexpectedEOF
	}, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}
	r.post([]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6}}) // must not panic

	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("server hit %d times, want 0 (bearer error short-circuits)", n)
	}
}
