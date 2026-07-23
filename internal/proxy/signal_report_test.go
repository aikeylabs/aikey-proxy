package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
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
	nilR.enqueue("c1", 100, 0.5, nil) // must not panic

	// empty credentialID is dropped — observable via the buffered channel.
	r := &signalReporter{in: make(chan signalSample, 4)}
	r.enqueue("", 100, 0.5, nil)
	if len(r.in) != 0 {
		t.Fatalf("empty credentialID should be dropped, buffered = %d", len(r.in))
	}
	r.enqueue("c1", 100, 0.5, nil)
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
	r.post([]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6}}, nil, nil, nil)

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
	r.post([]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6}}, nil, nil, nil) // must not panic

	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("server hit %d times, want 0 (bearer error short-circuits)", n)
	}
}

func TestEnqueueRevokedNilEmptyAndNonBlocking(t *testing.T) {
	// nil receiver guard: feature-off reporter must not panic.
	var nilR *signalReporter
	nilR.enqueueRevoked("c1", "revoked") // must not panic

	// empty credentialID is dropped; valid one is queued; empty reason defaults.
	r := &signalReporter{revokedIn: make(chan revokedSample, 4)}
	r.enqueueRevoked("", "revoked")
	if len(r.revokedIn) != 0 {
		t.Fatalf("empty credentialID should be dropped, buffered = %d", len(r.revokedIn))
	}
	r.enqueueRevoked("c1", "") // empty reason → defaults to "revoked"
	if len(r.revokedIn) != 1 {
		t.Fatalf("valid revoked should be queued, buffered = %d", len(r.revokedIn))
	}
	if rv := <-r.revokedIn; rv != (revokedSample{CredentialID: "c1", Reason: "revoked"}) {
		t.Fatalf("queued = %+v, want {c1, revoked}", rv)
	}

	// non-blocking: a full buffer drops rather than blocks the forward path.
	full := &signalReporter{revokedIn: make(chan revokedSample, 1)}
	full.enqueueRevoked("c1", "revoked")
	full.enqueueRevoked("c2", "revoked") // buffer full → dropped, must not block
	if len(full.revokedIn) != 1 {
		t.Fatalf("full buffer should drop, buffered = %d", len(full.revokedIn))
	}
}

func TestSignalPostSendsRevoked(t *testing.T) {
	type captured struct {
		method string
		auth   string
		body   []byte
	}
	got := make(chan captured, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got <- captured{req.Method, req.Header.Get("Authorization"), b}
	}))
	defer srv.Close()

	r := newSignalReporter(srv.URL, func(context.Context) (string, error) { return "tok-123", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}

	// all-revoked batch: body omits "samples" and carries only "revoked".
	r.post(nil, []revokedSample{{CredentialID: "c1", Reason: "revoked"}}, nil, nil)
	c := <-got
	if c.method != http.MethodPost {
		t.Errorf("method = %q, want POST", c.method)
	}
	if c.auth != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want %q", c.auth, "Bearer tok-123")
	}
	if want := `{"revoked":[{"credential_id":"c1","reason":"revoked"}]}`; string(c.body) != want {
		t.Fatalf("body = %s, want %s", c.body, want)
	}

	// mixed batch: both arrays serialize.
	r.post([]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6}},
		[]revokedSample{{CredentialID: "c2", Reason: "revoked"}}, nil, nil)
	c = <-got
	var decoded struct {
		Samples []signalSample  `json:"samples"`
		Revoked []revokedSample `json:"revoked"`
	}
	if err := json.Unmarshal(c.body, &decoded); err != nil {
		t.Fatalf("body not valid JSON: %v (raw %s)", err, c.body)
	}
	if len(decoded.Samples) != 1 || decoded.Samples[0] != (signalSample{CredentialID: "c1", TS: 100, Util5h: 0.6}) {
		t.Fatalf("decoded samples = %+v, want one {c1,100,0.6}", decoded.Samples)
	}
	if len(decoded.Revoked) != 1 || decoded.Revoked[0] != (revokedSample{CredentialID: "c2", Reason: "revoked"}) {
		t.Fatalf("decoded revoked = %+v, want one {c2,revoked}", decoded.Revoked)
	}
}

func TestIncrRateLimitNilAndEmpty(t *testing.T) {
	// nil receiver guard: feature-off reporter must not panic.
	var nilR *signalReporter
	nilR.incrRateLimit("c1") // must not panic

	// nil rlCounts map → incrRateLimit must lazy-init, not panic; empty id drops.
	r := &signalReporter{}
	r.incrRateLimit("") // empty credentialID dropped (no lazy-init needed)
	if len(r.snapshotRateLimits()) != 0 {
		t.Fatal("empty credentialID should be dropped")
	}
	r.incrRateLimit("c1") // lazy-inits the map
	if rl := r.snapshotRateLimits(); len(rl) != 1 || rl[0].Count != 1 {
		t.Fatalf("after lazy init = %+v, want one {c1, count 1}", rl)
	}
}

func TestRateLimitCounting(t *testing.T) {
	r := &signalReporter{rlCounts: make(map[string]int)}
	// two 429s + one 403 for c1 → count 3; c2 is never seen → stays absent.
	r.incrRateLimit("c1")
	r.incrRateLimit("c1")
	r.incrRateLimit("c1")
	rl := r.snapshotRateLimits()
	if len(rl) != 1 {
		t.Fatalf("snapshot = %+v, want exactly one entry", rl)
	}
	if rl[0] != (rateLimitSample{CredentialID: "c1", Count: 3, WindowSecs: 30}) {
		t.Fatalf("snapshot[0] = %+v, want {c1, 3, 30}", rl[0])
	}
}

func TestRateLimitResetAfterFlush(t *testing.T) {
	r := &signalReporter{rlCounts: make(map[string]int)}
	r.incrRateLimit("c1")
	r.incrRateLimit("c1")
	if rl := r.snapshotRateLimits(); len(rl) != 1 || rl[0].Count != 2 {
		t.Fatalf("first window = %+v, want c1 count 2", rl)
	}
	// next window starts empty (counter was reset on snapshot).
	if rl := r.snapshotRateLimits(); rl != nil {
		t.Fatalf("after flush snapshot = %+v, want nil (reset)", rl)
	}
	// new increments count up from 0, not from the prior window.
	r.incrRateLimit("c1")
	if rl := r.snapshotRateLimits(); len(rl) != 1 || rl[0].Count != 1 {
		t.Fatalf("second window = %+v, want c1 count 1", rl)
	}
}

func TestRateLimitConcurrent(t *testing.T) {
	// map+mutex concurrency smoke: many goroutines incrementing the same
	// credential must total exactly N*per (run under -race to catch data races).
	r := &signalReporter{rlCounts: make(map[string]int)}
	const goroutines, per = 8, 100
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < per; j++ {
				r.incrRateLimit("c1")
			}
		}()
	}
	wg.Wait()
	rl := r.snapshotRateLimits()
	if len(rl) != 1 || rl[0].Count != goroutines*per {
		t.Fatalf("concurrent count = %+v, want one {c1, %d}", rl, goroutines*per)
	}
}

func TestSignalPostSendsRateLimits(t *testing.T) {
	got := make(chan []byte, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got <- b
	}))
	defer srv.Close()

	r := newSignalReporter(srv.URL, func(context.Context) (string, error) { return "tok-123", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}

	// rate-limits-only batch: body omits samples + revoked, exact wire contract.
	r.post(nil, nil, []rateLimitSample{{CredentialID: "c1", Count: 3, WindowSecs: 30}}, nil)
	if want := `{"rate_limits":[{"credential_id":"c1","count":3,"window_secs":30}]}`; string(<-got) != want {
		t.Fatalf("rate-limits-only body mismatch, want %s", want)
	}

	// mixed batch: samples + revoked + rate_limits all serialize.
	r.post([]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6}},
		[]revokedSample{{CredentialID: "c2", Reason: "revoked"}},
		[]rateLimitSample{{CredentialID: "c3", Count: 5, WindowSecs: 30}}, nil)
	var decoded struct {
		Samples    []signalSample    `json:"samples"`
		Revoked    []revokedSample   `json:"revoked"`
		RateLimits []rateLimitSample `json:"rate_limits"`
	}
	body := <-got
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body not valid JSON: %v (raw %s)", err, body)
	}
	if len(decoded.Samples) != 1 || decoded.Samples[0] != (signalSample{CredentialID: "c1", TS: 100, Util5h: 0.6}) {
		t.Fatalf("decoded samples = %+v, want one {c1,100,0.6}", decoded.Samples)
	}
	if len(decoded.Revoked) != 1 || decoded.Revoked[0] != (revokedSample{CredentialID: "c2", Reason: "revoked"}) {
		t.Fatalf("decoded revoked = %+v, want one {c2,revoked}", decoded.Revoked)
	}
	if len(decoded.RateLimits) != 1 || decoded.RateLimits[0] != (rateLimitSample{CredentialID: "c3", Count: 5, WindowSecs: 30}) {
		t.Fatalf("decoded rate_limits = %+v, want one {c3,5,30}", decoded.RateLimits)
	}
}

func TestIsHardRevoked(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		errType string
		errMsg  string
		want    bool
	}{
		{"401_revoked_msg", 401, "authentication_error", "OAuth token has been revoked", true},
		{"401_revoked_in_type", 401, "token_revoked", "", true},
		{"401_plain_expiry", 401, "authentication_error", "token expired", false},
		{"429_revoked", 429, "", "revoked", false},
		{"200_ok", 200, "", "", false},
		// codex/openai hard-revocation shapes (sub2api-derived, R37 2026-07-04):
		// errMsg is the raw body. token_invalidated has NO "revoked" substring, so
		// the old matcher missed it; the {"detail":"Unauthorized"} form is
		// non-standard (no error envelope at all).
		{"401_codex_token_invalidated", 401, "", `{"error":{"code":"token_invalidated"}}`, true},
		{"401_codex_token_revoked_code", 401, "", `{"error":{"code":"token_revoked"}}`, true},
		{"401_codex_detail_unauthorized", 401, "", `{"detail":"Unauthorized"}`, true},
		// a plain codex 401 (transient / refresh-recoverable) must NOT quarantine.
		{"401_codex_plain", 401, "", `{"error":{"message":"invalid token"}}`, false},
		{"401_generic_unauthorized_word", 401, "", "request was unauthorized, please retry", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHardRevoked(tt.status, tt.errType, tt.errMsg); got != tt.want {
				t.Fatalf("isHardRevoked(%d,%q,%q) = %v, want %v", tt.status, tt.errType, tt.errMsg, got, tt.want)
			}
		})
	}
}

func TestParseUnifiedUtil7d(t *testing.T) {
	const hdr = "anthropic-ratelimit-unified-7d-utilization"
	tests := []struct {
		name   string
		set    bool
		val    string
		wantV  float64
		wantOK bool
	}{
		{"valid", true, "0.42", 0.42, true},
		{"missing", false, "", 0, false},
		{"malformed", true, "xyz", 0, false},
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
			v, ok := parseUnifiedUtil7d(h)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && v != tt.wantV {
				t.Fatalf("v = %v, want %v", v, tt.wantV)
			}
		})
	}
}

func TestSignalSampleUtil7dSerialization(t *testing.T) {
	// both readings present → both serialize, util_7d after util_5h.
	u7d := 0.4
	both, _ := json.Marshal(signalSample{CredentialID: "c1", TS: 100, Util5h: 0.6, Util7d: &u7d})
	if want := `{"credential_id":"c1","ts":100,"util_5h":0.6,"util_7d":0.4}`; string(both) != want {
		t.Fatalf("both = %s, want %s", both, want)
	}
	// 5h-only (no 7d header) → util_7d omitempty drops it, byte-identical to the
	// pre-7d wire format so existing master ingest is unaffected.
	only, _ := json.Marshal(signalSample{CredentialID: "c1", TS: 100, Util5h: 0.6})
	if want := `{"credential_id":"c1","ts":100,"util_5h":0.6}`; string(only) != want {
		t.Fatalf("5h-only = %s, want %s", only, want)
	}
}

func TestConcurrencyPeak(t *testing.T) {
	r := &signalReporter{} // lazy-init path (no maps preallocated)
	// start, start → peak 2; one ends → cur 1; start → cur 2 (peak stays 2).
	d1 := r.trackInflight("c1")
	d2 := r.trackInflight("c1")
	d1()                        // one completes → cur 1
	d3 := r.trackInflight("c1") // back to cur 2
	snap := r.snapshotConcurrency()
	if len(snap) != 1 || snap[0] != (concurrencySample{CredentialID: "c1", Peak: 2}) {
		t.Fatalf("snapshot = %+v, want one {c1, peak 2}", snap)
	}
	// next window: peak map reset. d2/d3 are still in flight (cur 2) but with no
	// NEW arrival the idle window reports nothing — peak only bumps on inc (the
	// documented ponytail steady-state-trough ceiling). Pins that behavior.
	if snap2 := r.snapshotConcurrency(); snap2 != nil {
		t.Fatalf("idle next window = %+v, want nil (peak reset)", snap2)
	}
	d2()
	d3() // cur back to 0
	// a fresh request in the new window peaks at 1 (cur started from 0).
	d4 := r.trackInflight("c1")
	if snap3 := r.snapshotConcurrency(); len(snap3) != 1 || snap3[0].Peak != 1 {
		t.Fatalf("new window = %+v, want c1 peak 1", snap3)
	}
	d4()
}

func TestConcurrencyPeakNilAndEmpty(t *testing.T) {
	// nil receiver guard: feature-off reporter must not panic, returns a usable
	// no-op so callers can `defer trackInflight(id)()` unconditionally.
	var nilR *signalReporter
	nilR.trackInflight("c1")() // must not panic

	// empty credentialID → no-op, nothing tracked.
	r := &signalReporter{}
	r.trackInflight("")() // must not panic, no map entry
	if r.snapshotConcurrency() != nil {
		t.Fatal("empty credentialID should track nothing")
	}
}

func TestConcurrencyPeakConcurrent(t *testing.T) {
	// Deterministic peak under real concurrency: all goroutines hold their
	// in-flight slot simultaneously, so the peak is exactly `goroutines`. Run
	// under -race to catch a data race on the inflCur/inflPeak maps.
	r := &signalReporter{}
	const goroutines = 8
	release := make(chan struct{})
	var held, wg sync.WaitGroup
	held.Add(goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			done := r.trackInflight("c1")
			held.Done() // signal "I'm in flight"
			<-release   // hold until every goroutine is concurrently in flight
			done()
		}()
	}
	held.Wait() // all goroutines have incremented → cur == peak == goroutines
	snap := r.snapshotConcurrency()
	close(release)
	wg.Wait()
	if len(snap) != 1 || snap[0] != (concurrencySample{CredentialID: "c1", Peak: goroutines}) {
		t.Fatalf("concurrent peak = %+v, want one {c1, %d}", snap, goroutines)
	}
}

func TestSignalPostSendsConcurrency(t *testing.T) {
	got := make(chan []byte, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got <- b
	}))
	defer srv.Close()

	r := newSignalReporter(srv.URL, func(context.Context) (string, error) { return "tok-123", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}

	// concurrency-only batch: body omits the other three, exact wire contract.
	r.post(nil, nil, nil, []concurrencySample{{CredentialID: "c1", Peak: 2}})
	if want := `{"concurrency":[{"credential_id":"c1","peak":2}]}`; string(<-got) != want {
		t.Fatalf("concurrency-only body mismatch, want %s", want)
	}

	// mixed all-four batch: samples (with util_7d) + revoked + rate_limits +
	// concurrency all serialize.
	u7d := 0.4
	r.post(
		[]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6, Util7d: &u7d}},
		[]revokedSample{{CredentialID: "c2", Reason: "revoked"}},
		[]rateLimitSample{{CredentialID: "c3", Count: 5, WindowSecs: 30}},
		[]concurrencySample{{CredentialID: "c4", Peak: 2}})
	var decoded struct {
		Samples     []signalSample      `json:"samples"`
		Revoked     []revokedSample     `json:"revoked"`
		RateLimits  []rateLimitSample   `json:"rate_limits"`
		Concurrency []concurrencySample `json:"concurrency"`
	}
	body := <-got
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body not valid JSON: %v (raw %s)", err, body)
	}
	if len(decoded.Samples) != 1 || decoded.Samples[0].CredentialID != "c1" || decoded.Samples[0].TS != 100 ||
		decoded.Samples[0].Util5h != 0.6 || decoded.Samples[0].Util7d == nil || *decoded.Samples[0].Util7d != 0.4 {
		t.Fatalf("decoded samples = %+v, want one {c1,100,0.6,0.4}", decoded.Samples)
	}
	if len(decoded.Revoked) != 1 || decoded.Revoked[0] != (revokedSample{CredentialID: "c2", Reason: "revoked"}) {
		t.Fatalf("decoded revoked = %+v, want one {c2,revoked}", decoded.Revoked)
	}
	if len(decoded.RateLimits) != 1 || decoded.RateLimits[0] != (rateLimitSample{CredentialID: "c3", Count: 5, WindowSecs: 30}) {
		t.Fatalf("decoded rate_limits = %+v, want one {c3,5,30}", decoded.RateLimits)
	}
	if len(decoded.Concurrency) != 1 || decoded.Concurrency[0] != (concurrencySample{CredentialID: "c4", Peak: 2}) {
		t.Fatalf("decoded concurrency = %+v, want one {c4,2}", decoded.Concurrency)
	}
}

// TestSignalReporterCloseIdempotentAndNilSafe covers the leak-fix Close contract:
// loop() now returns on <-r.stop (so the per-generation goroutine + ticker don't
// leak across reloads), and Close must be safe to call more than once
// (generation.close paths) and on a nil receiver (feature-off). The concrete risk
// is a double close(r.stop) panic — guarded by stopOnce; this test fails if that
// guard is removed. (loop()'s timing isn't deterministically testable — see the
// file header — so the stop case itself is verified by inspection.)
func TestSignalReporterCloseIdempotentAndNilSafe(t *testing.T) {
	r := newSignalReporter("http://example.invalid", func(context.Context) (string, error) { return "tok", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := r.Close(); err != nil { // idempotent — must not panic on double close
		t.Fatalf("second Close: %v", err)
	}
	var nilR *signalReporter
	if err := nilR.Close(); err != nil { // nil-safe — feature-off passes a nil reporter
		t.Fatalf("nil Close: %v", err)
	}
}
