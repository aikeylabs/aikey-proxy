package server

import (
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// AdminGate authenticates the control-plane (/admin/*) routes.
//
// # Why this exists (2026-08-03)
//
// The admin mux is registered on the SAME listener as the data plane, and a
// cluster worker MUST bind that listener publicly: form-① clients connect
// straight to <node public IP>:27200, and the hub hands them that address.
// So every /admin/* route was reachable, unauthenticated, from the internet.
// Verified against staging worker-1 from outside the VPC: 12 routes answered
// 200, including
//
//	PUT /admin/upstream-proxy   — validates, PERSISTS to aikey-user.yaml, and
//	                              HOT-SWAPS the live transport. Point egress at
//	                              your own host and every upstream call, carrying
//	                              decrypted provider keys, flows through you —
//	                              and survives restart.
//	POST /admin/debug/upstream-headers — switches on request_body logging.
//	POST /admin/probe/ping, /admin/egress-test — dial arbitrary hosts from the
//	                              node's network position (inside the VPC).
//
// The code believed it was protected: internal/admin/handlers.go states
// "worker nginx denies /admin/* (P3 方案C)". No such rule exists — workers run
// no nginx at all, and the shipped cluster ingress template has no admin rule.
// The one place it IS handled is the OAuth-routing sidecar allowlist, which
// only ever sees form-③ traffic arriving via the master ingress.
//
// # Why a token and not a loopback bind
//
// Binding admin to loopback/private cannot work here. The master reaches a node
// at its HUB-REGISTERED ADVERTISED address — the public IP, by the form-①
// advertise rule — for POST /admin/egress-test (the Nodes page Test button) and
// for pushing node egress config. A loopback-only bind would break both, and
// would break them silently until an admin clicked Test.
//
// # Fail-closed
//
// An unconfigured Token rejects every non-loopback request. A gate that waved
// traffic through whenever it was unconfigured would be indistinguishable from
// no gate on exactly the nodes that never got the config — which is the
// population most likely to be exposed.
//
// # Known limitation, stated rather than hidden
//
// Token is the cluster's control service token: a SHARED secret that the master
// and every node already hold, so this needs no new distribution. It is
// therefore symmetric — a compromised node can present it to another node. That
// is materially better than no authentication, and worse than per-node
// credentials. Recorded so the next person does not mistake it for mutual auth.
type AdminGate struct {
	// Token is the node's control_service_token. Empty ⇒ no remote admin access.
	Token string
}

// loopbackOK reports whether the peer is the local host, in which case the
// caller is the CLI (`aikey doctor`, `aikey test`), the local web Settings card
// or the Personal edition's own control service — all of which reach the proxy
// over 127.0.0.1 and have always been unauthenticated. Keeping them exempt is
// what makes this change invisible to single-machine editions.
func loopbackOK(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// presentedToken pulls the credential from either header. Authorization is the
// conventional one; X-Aikey-Service-Token exists because the data plane on this
// same listener already treats Authorization as the caller's VIRTUAL KEY, and a
// control-plane call must not be ambiguous with one.
func presentedToken(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Aikey-Service-Token")); v != "" {
		return v
	}
	v := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return ""
}

// guard wraps a control-plane handler with the gate.
func (g AdminGate) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if loopbackOK(r) {
			next(w, r)
			return
		}
		if g.Token == "" {
			slog.Warn("admin: remote control-plane request refused — no control_service_token configured on this node",
				"event.name", "proxy.admin.unauthenticated_refused",
				"path", r.URL.Path, "remote_addr", r.RemoteAddr)
			writeAdminAuthErr(w, "this node has no control_service_token configured, so remote admin access is refused")
			return
		}
		got := presentedToken(r)
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(g.Token)) != 1 {
			slog.Warn("admin: remote control-plane request refused — bad or missing service token",
				"event.name", "proxy.admin.unauthenticated_refused",
				"path", r.URL.Path, "remote_addr", r.RemoteAddr, "token_presented", got != "")
			writeAdminAuthErr(w, "control-plane routes require the cluster control service token")
			return
		}
		next(w, r)
	}
}

func writeAdminAuthErr(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":{"type":"authentication_error","code":"ADMIN_TOKEN_REQUIRED","message":"` + msg + `"},"origin":"worker-proxy.ADMIN_TOKEN_REQUIRED"}`))
}
