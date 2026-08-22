package supervisor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// A revoked credential must STOP the rail, not be retried forever.
//
// 🔴 WHY THIS FENCE EXISTS (2026-08-22). Found live on a developer machine:
// GET <control>/v1/fallback-policy answered 403 {"error":"BIZ_AUTH_TOKEN_REVOKED"}
// and this rail re-asked every cycle for FORTY-EIGHT DAYS — 180 consecutive
// failures when it was finally noticed. (⚠️ 2026-08-22 correction: the 466 MB log on that machine was NOT this rail. observe() rate-limits to one line per 60 failures, which cannot reach that size; the bulk was a per-second "authentication failed: missing virtual key" from a leaked test proxy. The rail's defect — retrying a deterministic refusal forever — is real and unchanged; only the log-size attribution was wrong.) The log line was of that one
// repeated line. Nothing else showed a symptom: rails never gate serving (by
// design, and correctly), so the machine kept working the whole time.
//
// The defect was treating a DETERMINISTIC REFUSAL as a transient outage. This
// test pins the distinction at both layers, because the fix spans both:
//   - the rail must MARK a 403 as terminal (wrap errRailCredentialRevoked)
//   - railset must ACT on that mark (state → needs_reauth, stop polling)
//
// Testing only one layer would let the other regress silently — the same
// "two implementations, one tested" trap this repo has been bitten by before.
// A 403 that does NOT name the revocation must stay retryable.
//
// 🔴 Found by review, 2026-08-22: aikey-trial-server answers a PLAIN TEXT 403
// "Host not allowed" for any non-loopback Host (serve/middleware.go:40). A seat
// pointed at a LAN Trial console hits that every cycle — and the first cut of
// this fix would have called it a revoked credential and told the operator to
// run `aikey login`, which fixes nothing. Status alone is not evidence.
func TestForbiddenWithoutTheRevokedCodeStaysRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Host not allowed"))
	}))
	defer srv.Close()

	s := &Supervisor{fallbackPolicy: proxy.NewFallbackPolicyCache(nil)}
	err := s.syncFallbackPolicy(context.Background(), nil, srv.URL, "seat-bearer")
	if err == nil {
		t.Fatal("a 403 must still be an error")
	}
	if errors.Is(err, errRailCredentialRevoked) {
		t.Fatalf("a bare 403 was marked as a revoked credential: %v\n"+
			"that sends the operator to `aikey login` for a wrong Host or a DB blip", err)
	}
}

func TestRevoked403StopsTheRailInsteadOfRetryingForever(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"BIZ_AUTH_TOKEN_REVOKED","message":"token has been revoked"}`))
	}))
	defer srv.Close()

	s := &Supervisor{fallbackPolicy: proxy.NewFallbackPolicyCache(nil)}

	// Layer 1 — the rail must label the refusal terminal.
	err := s.syncFallbackPolicy(context.Background(), nil, srv.URL, "seat-bearer")
	if err == nil {
		t.Fatal("a 403 must be an error")
	}
	if !errors.Is(err, errRailCredentialRevoked) {
		t.Fatalf("403 was not marked terminal: %v\n"+
			"a revoked credential retried as if transient is how this rail burned 48 days and 466 MB", err)
	}

	// Layer 2 — railset must act on the mark and stop.
	r := &railRunner{spec: railSpec{name: "fallback_policy"}}
	r.observe(err)
	if got := r.state; got != railNeedsReauth {
		t.Fatalf("rail state = %v, want needs_reauth — the mark was set but nothing acted on it", got)
	}
	if !r.isTerminal() {
		t.Fatal("isTerminal() false after a refusal — cycle() would keep polling every cycle, which is the 466 MB log")
	}

	// 🔴 …but it must NOT be permanent. The control plane answers
	// BIZ_AUTH_TOKEN_REVOKED for every org-resolution failure, including a
	// transient database error (handler_fallback_policy.go:155), so a refusal
	// that stops forever would turn a one-second blip into a rail that never
	// recovers — and `aikey login`, the advice we print, would not fix it.
	// Walk the skip counter to the re-probe point and require a cycle through.
	reprobed := false
	for i := 0; i < terminalReprobeEveryCycles*2; i++ {
		if !r.isTerminal() {
			reprobed = true
			break
		}
	}
	if !reprobed {
		t.Fatalf("rail never re-probed after %d cycles — a transient 403 would strand it forever",
			terminalReprobeEveryCycles*2)
	}

	// A successful re-probe must clear the refused state completely.
	r.observe(nil)
	if r.state != railOK {
		t.Fatalf("state = %v after a successful re-probe, want ok", r.state)
	}
}
