package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// probe returns a handler that records whether it was ever reached, so these
// tests assert REACHABILITY rather than a status code some middleware could
// fake.
func probe(reached *bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	}
}

func call(h http.HandlerFunc, remoteAddr, header, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, "/admin/upstream-proxy", strings.NewReader(`{"url":""}`))
	r.RemoteAddr = remoteAddr
	if header != "" {
		r.Header.Set(header, token)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// TestAdminGate_RemoteUnauthenticatedIsRefused is the whole point: before this
// gate, PUT /admin/upstream-proxy from the public internet reached the handler
// and hot-swapped the node's egress.
func TestAdminGate_RemoteUnauthenticatedIsRefused(t *testing.T) {
	var reached bool
	g := AdminGate{Token: "s3cret"}
	w := call(g.guard(probe(&reached)), "203.0.113.9:51000", "", "")

	if reached {
		t.Error("🔴 an unauthenticated REMOTE request reached the admin handler. " +
			"On a cluster worker that listener is on the public internet, and this route " +
			"persists + hot-swaps the node's upstream proxy — i.e. redirects every " +
			"upstream call, carrying decrypted provider keys, through the caller's host.")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAdminGate_RemoteWithCorrectTokenIsAllowed(t *testing.T) {
	g := AdminGate{Token: "s3cret"}
	for _, tc := range []struct{ name, header, token string }{
		{"authorization bearer", "Authorization", "Bearer s3cret"},
		{"service token header", "X-Aikey-Service-Token", "s3cret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reached bool
			w := call(g.guard(probe(&reached)), "10.0.0.93:51000", tc.header, tc.token)
			if !reached {
				t.Errorf("the master could not reach the admin handler with a valid token (status %d). "+
					"That breaks the Nodes page Test button and the node-egress push.", w.Code)
			}
		})
	}
}

func TestAdminGate_RemoteWithWrongTokenIsRefused(t *testing.T) {
	var reached bool
	g := AdminGate{Token: "s3cret"}
	w := call(g.guard(probe(&reached)), "203.0.113.9:51000", "Authorization", "Bearer wrong")
	if reached {
		t.Error("a WRONG token reached the handler")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestAdminGate_LoopbackIsExempt keeps single-machine editions working. The
// CLI (`aikey doctor`, `aikey test`), the local web Settings card and the
// Personal control service all call these routes over 127.0.0.1 and have never
// carried a token.
func TestAdminGate_LoopbackIsExempt(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:44444", "[::1]:44444"} {
		t.Run(addr, func(t *testing.T) {
			var reached bool
			// No token configured AND no credential presented — the exact shape of
			// a Personal install.
			w := call(AdminGate{}.guard(probe(&reached)), addr, "", "")
			if !reached {
				t.Errorf("loopback caller was refused (status %d) — this would break "+
					"`aikey doctor`, the local Settings card and Personal edition entirely", w.Code)
			}
		})
	}
}

// TestAdminGate_FailsClosedWhenNoTokenConfigured is the rollout decision made
// explicit. A node upgraded before its master, or installed by an older
// installer, has no control_service_token. It must refuse remote admin traffic
// rather than wave it through.
//
// 🔴 The tempting alternative — "no token configured ⇒ allow, we'll enforce
// next release" — leaves the hole open on precisely the nodes nobody
// configured, which is the population most likely to be exposed.
func TestAdminGate_FailsClosedWhenNoTokenConfigured(t *testing.T) {
	var reached bool
	w := call(AdminGate{Token: ""}.guard(probe(&reached)), "203.0.113.9:51000", "Authorization", "Bearer anything")
	if reached {
		t.Error("🔴 FAIL-OPEN: a node with no configured token let a remote caller through")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "control_service_token") {
		t.Errorf("the refusal must name the missing config key so an operator can act on it; got %s", w.Body.String())
	}
}

// TestAdminGate_EveryAdminRouteIsGuarded is the structural half. Counting
// guarded routes by hand rots; this drives the REAL mux and asserts that
// nothing under /admin/ answers an unauthenticated remote caller.
//
// 🚫 Without this, adding one unguarded mux.HandleFunc("… /admin/…") in six
// months silently reopens the hole, and every test above still passes.
func TestAdminGate_EveryAdminRouteIsGuarded(t *testing.T) {
	routes := adminRoutePatterns(t)
	if len(routes) == 0 {
		t.Fatal("anti-vacuous: no /admin routes discovered in server.go — the scan is broken, " +
			"and a scan that finds nothing would pass no matter how many routes were exposed")
	}
	for _, rt := range routes {
		if !strings.Contains(rt.expr, "gate.guard(") {
			t.Errorf("🔴 UNGUARDED control-plane route: %s %s\n"+
				"  registered as: %s\n"+
				"  On a cluster worker this is reachable from the public internet.",
				rt.method, rt.path, rt.expr)
		}
	}
	t.Logf("all %d /admin/* route registrations pass through the gate", len(routes))
}
