package events

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// newTestReporter builds a real Reporter backed by a temp WAL dir. The canary
// only needs Report() to not panic (it writes to the WAL outbox); the outcome
// under test comes from the diagnostics HTTP server, not from upload.
func newTestReporter(t *testing.T) *Reporter {
	t.Helper()
	r, err := NewReporter(ReporterConfig{
		WALDir:         t.TempDir(),
		UploadInterval: time.Hour, // keep the upload loop idle during the test
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// newProbeNoLoop constructs a CanaryProbe without starting its background loop,
// so the test can drive probe() deterministically one outcome at a time. It
// reuses the real production probe()/checkArrival() code — no reimplementation.
func newProbeNoLoop(reporter *Reporter, diagnosticsURL string) *CanaryProbe {
	return &CanaryProbe{
		reporter: reporter,
		cfg: CanaryConfig{
			DiagnosticsURL: diagnosticsURL,
			Interval:       time.Hour,
			CheckDelay:     time.Millisecond, // don't wait 15s in tests
		},
		client: &http.Client{Timeout: 2 * time.Second},
		done:   make(chan struct{}),
	}
}

// TestCanaryConsecutiveFailuresSurfacedInResult asserts the streak is written
// into CanaryResult (so /metrics, which serializes CanaryResult, exposes it).
func TestCanaryConsecutiveFailuresSurfacedInResult(t *testing.T) {
	reporter := newTestReporter(t)

	// Diagnostics server that returns 200 but reports the event never reached
	// ODS → result.Status == "failed", which increments consecutiveFailures.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ods_received":false,"dwd_projected":false}`))
	}))
	defer srv.Close()

	p := newProbeNoLoop(reporter, srv.URL)

	p.probe()
	if got := p.LastResult().ConsecutiveFailures; got != 1 {
		t.Fatalf("after 1 failed probe: ConsecutiveFailures=%d, want 1", got)
	}
	p.probe()
	res := p.LastResult()
	if res.Status != "failed" {
		t.Fatalf("status=%q, want failed", res.Status)
	}
	if res.ConsecutiveFailures != 2 {
		t.Fatalf("after 2 failed probes: ConsecutiveFailures=%d, want 2", res.ConsecutiveFailures)
	}
}

// TestCanaryStreakResetsOnRecovery asserts an "ok" probe clears the streak and
// it is reflected in the surfaced CanaryResult field.
func TestCanaryStreakResetsOnRecovery(t *testing.T) {
	reporter := newTestReporter(t)

	var ok bool
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		body := `{"ods_received":false,"dwd_projected":false}`
		if ok {
			body = `{"ods_received":true,"dwd_projected":true}`
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	p := newProbeNoLoop(reporter, srv.URL)
	p.probe()
	p.probe()
	if got := p.LastResult().ConsecutiveFailures; got != 2 {
		t.Fatalf("ConsecutiveFailures=%d, want 2", got)
	}

	mu.Lock()
	ok = true
	mu.Unlock()
	p.probe()
	res := p.LastResult()
	if res.Status != "ok" {
		t.Fatalf("status=%q, want ok", res.Status)
	}
	if res.ConsecutiveFailures != 0 {
		t.Fatalf("after recovery: ConsecutiveFailures=%d, want 0", res.ConsecutiveFailures)
	}
}

// TestCanarySustainedUnavailableEscalatesAfterThreshold asserts a permanently
// unreachable/misconfigured diagnostics endpoint (404) escalates exactly once
// after unavailableEscalateThreshold consecutive "unavailable" outcomes — and
// that it never counts toward the pipeline-failure streak (intentional).
func TestCanarySustainedUnavailableEscalatesAfterThreshold(t *testing.T) {
	reporter := newTestReporter(t)

	// 404 → "unavailable" branch (misconfigured DiagnosticsURL / wrong service).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := newProbeNoLoop(reporter, srv.URL)

	for i := 0; i < unavailableEscalateThreshold-1; i++ {
		p.probe()
		if p.LastResult().Status != "unavailable" {
			t.Fatalf("probe %d: status=%q, want unavailable", i, p.LastResult().Status)
		}
		p.mu.RLock()
		escalated := p.unavailableEscalated
		failures := p.consecutiveFailures
		p.mu.RUnlock()
		if escalated {
			t.Fatalf("escalated early after %d probes (threshold=%d)", i+1, unavailableEscalateThreshold)
		}
		if failures != 0 {
			t.Fatalf("unavailable must not count toward pipeline streak; consecutiveFailures=%d", failures)
		}
	}

	// The threshold-crossing probe escalates exactly once.
	p.probe()
	p.mu.RLock()
	escalated := p.unavailableEscalated
	unavail := p.consecutiveUnavailable
	failures := p.consecutiveFailures
	p.mu.RUnlock()
	if !escalated {
		t.Fatalf("expected escalation at threshold=%d (consecutive_unavailable=%d)", unavailableEscalateThreshold, unavail)
	}
	if failures != 0 {
		t.Fatalf("unavailable must not count toward pipeline streak; consecutiveFailures=%d", failures)
	}

	// Further unavailable probes stay escalated but do not re-escalate (no spam):
	// unavailableEscalated remains true and the counter keeps climbing.
	p.probe()
	p.mu.RLock()
	if !p.unavailableEscalated || p.consecutiveUnavailable != unavailableEscalateThreshold+1 {
		t.Fatalf("after extra probe: escalated=%v unavail=%d (want escalated, %d)",
			p.unavailableEscalated, p.consecutiveUnavailable, unavailableEscalateThreshold+1)
	}
	p.mu.RUnlock()
}

// TestCanaryUnavailableStreakResetsOnRealOutcome asserts a real pipeline
// outcome (failed) clears the unavailable streak and re-arms escalation.
func TestCanaryUnavailableStreakResetsOnRealOutcome(t *testing.T) {
	reporter := newTestReporter(t)

	var status int = http.StatusNotFound // start unavailable
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		s := status
		mu.Unlock()
		if s == http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ods_received":false,"dwd_projected":false}`)) // 200 but failed pipeline
			return
		}
		w.WriteHeader(s)
	}))
	defer srv.Close()

	p := newProbeNoLoop(reporter, srv.URL)
	for i := 0; i < unavailableEscalateThreshold; i++ {
		p.probe()
	}
	p.mu.RLock()
	if !p.unavailableEscalated {
		p.mu.RUnlock()
		t.Fatal("expected escalation before reset")
	}
	p.mu.RUnlock()

	// Switch to a real pipeline failure → unavailable streak must reset.
	mu.Lock()
	status = http.StatusOK
	mu.Unlock()
	p.probe()
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.consecutiveUnavailable != 0 || p.unavailableEscalated {
		t.Fatalf("real outcome must reset unavailable streak; unavail=%d escalated=%v",
			p.consecutiveUnavailable, p.unavailableEscalated)
	}
	if p.consecutiveFailures != 1 {
		t.Fatalf("real failed outcome should increment pipeline streak; consecutiveFailures=%d", p.consecutiveFailures)
	}
}
