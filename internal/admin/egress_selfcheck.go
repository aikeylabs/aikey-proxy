package admin

import "net/http"

// egress_selfcheck.go — the node-side per-account egress connectivity self-check
// (§5.4 of the fallback-group方案). A THIN control-plane endpoint: it enumerates
// the pool accounts' configured egress specs and, on demand, dials each once
// through the SHARED egress.TestDial (the same engine the proxy routes with — no
// re-implemented probe). Stateless: one-shot dial, no health-check loop.
//
// Two modes via ?dial=:
//   - presence (default, used by `aikey test` on the hot path): list which
//     accounts have egress configured + which engine handles it — NO network, so
//     the wrapper preflight stays fast and never probes on a regular cadence
//     (§5.4 #2 signature concern).
//   - dial=1 (used by `aikey doctor`, explicit): actually dial each spec and
//     report OK/fail + exit IP + latency, so the user can self-check reachability
//     and whether the paths share one exit IP.

// EgressCheckResult is one account's egress self-check row. Dialed=false rows are
// presence-only (OK/ExitIP/Latency unset). Reason carries the actionable failure
// detail (DNS / refused / timeout / auth / non-socks5 hop) — user-facing, no
// internal ids.
type EgressCheckResult struct {
	Label     string `json:"label"`
	Dialed    bool   `json:"dialed"`
	OK        bool   `json:"ok"`
	Engine    string `json:"engine,omitempty"`
	ExitIP    string `json:"exit_ip,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type egressSelfCheckBody struct {
	Dialed bool                `json:"dialed"`
	Paths  []EgressCheckResult `json:"paths"`
}

// EgressSelfCheck serves GET /admin/egress/selfcheck (loopback admin call from
// the CLI). ?dial=1 dials each account's egress; default is presence-only.
func (h *Handler) EgressSelfCheck(w http.ResponseWriter, r *http.Request) {
	dial := false
	switch r.URL.Query().Get("dial") {
	case "1", "true", "yes":
		dial = true
	}
	var paths []EgressCheckResult
	if h.EgressSelfCheckFn != nil {
		paths = h.EgressSelfCheckFn(r.Context(), dial)
	}
	if paths == nil {
		paths = []EgressCheckResult{}
	}
	writeJSON(w, http.StatusOK, egressSelfCheckBody{Dialed: dial, Paths: paths})
}
