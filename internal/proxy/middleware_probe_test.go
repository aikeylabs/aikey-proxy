package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Tests for isAikeyProbe — the single-line header check that gates usage-
// event emission for `aikey test`/`doctor`/`add` pre-flight traffic. The
// guard is trivial but its semantics are load-bearing: miss one emission
// site and probe traffic silently inflates counters + (for OAuth/team
// billable keys) looks like real work to the provider.

func TestIsAikeyProbe_HeaderPresent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(headerAikeyProbe, "1")
	if !isAikeyProbe(r) {
		t.Fatal("expected isAikeyProbe=true when header is set to 1")
	}
}

func TestIsAikeyProbe_HeaderAbsent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if isAikeyProbe(r) {
		t.Fatal("expected isAikeyProbe=false when header is absent")
	}
}

func TestIsAikeyProbe_HeaderZero(t *testing.T) {
	// Explicit "0" must NOT be treated as probe. We want the opt-in semantics
	// tight — only literal "1" turns reporting off. Anything else (empty,
	// "true", "yes", stray values) keeps normal reporting behavior so we
	// fail closed, not open.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(headerAikeyProbe, "0")
	if isAikeyProbe(r) {
		t.Fatal("X-Aikey-Probe: 0 must NOT be treated as probe — opt-in requires exact value '1'")
	}
}

func TestIsAikeyProbe_HeaderNonOne(t *testing.T) {
	for _, v := range []string{"true", "yes", "TRUE", "on", "probe"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(headerAikeyProbe, v)
		if isAikeyProbe(r) {
			t.Errorf("X-Aikey-Probe: %q must NOT be treated as probe", v)
		}
	}
}

func TestIsAikeyProbe_NilRequest(t *testing.T) {
	// The internal code paths never pass nil today, but defensive check —
	// a panic here on an edge case would bring down the whole proxy for a
	// single-request concern.
	if isAikeyProbe(nil) {
		t.Fatal("nil request should yield isAikeyProbe=false, not panic")
	}
}
