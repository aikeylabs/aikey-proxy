package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// upstreamProxyBody is the GET response / PUT request shape: {"url": "..."}.
// Empty url means "no egress proxy → direct".
type upstreamProxyBody struct {
	URL string `json:"url"`
	// Egress is the layered decision state (2026-07-08, read side only —
	// omitted when EgressStateFn isn't wired, keeping the legacy shape for
	// existing consumers like the web Settings prefill, which reads .url).
	Egress *EgressState `json:"egress,omitempty"`
}

// EgressState is the daemon-truth view of the egress proxy decision, layer by
// layer, consumed by `aikey env`. WHY daemon-truth matters: the daemon's env
// is the launchd/systemd spawn snapshot — usually NOT the user's shell env —
// so only the daemon itself can answer "which proxy do my requests use".
type EgressState struct {
	// ExplicitURL: layer 1 — the user-set upstream_proxy.url ("" = not set).
	ExplicitURL string `json:"explicit_url"`
	// EnvAuthoritative: layer 2 — true when the daemon env carries proxy vars
	// EXPLICITLY configured via ~/.aikey/proxy.env (CLI-marked at spawn).
	// Since the 2026-07-08 precedence refinement, ONLY those bypass OS
	// detection; inherited shell env is a below-system fallback (layer 4).
	EnvAuthoritative bool `json:"env_authoritative"`
	// EnvVars: the EXPLICIT (proxy.env) vars (credentials redacted).
	EnvVars map[string]string `json:"env_vars,omitempty"`
	// EnvInheritedVars: layer 4 — proxy vars inherited from the spawn shell
	// (.zshrc exports, stale terminals); consulted only when layers 1-3 are
	// all empty.
	EnvInheritedVars map[string]string `json:"env_inherited_vars,omitempty"`
	// System: layer 3 — the live OS system-proxy snapshot.
	SystemSupported bool   `json:"system_supported"`
	SystemHTTP      string `json:"system_http,omitempty"`
	SystemHTTPS     string `json:"system_https,omitempty"`
	SystemSOCKS     string `json:"system_socks,omitempty"`
	// Effective: the resolved result for https provider targets, computed via
	// the SAME ProxyFunc the forwarding transport uses. Source is one of
	// "explicit" | "env" | "system" | "env_inherited" | "direct"; URL is ""
	// when direct.
	EffectiveSource string `json:"effective_source"`
	EffectiveURL    string `json:"effective_url,omitempty"`
	// MultiProtocol: true when this build has the enterprise multi-protocol
	// (mihomo) egress engine. The /user/settings upstream editor gates its
	// affordances on this — a multi-line spec box (socks5 chain / ss/vmess/trojan
	// config fragment, aligned with the master per-account editor) when true; a
	// single-URL input when false (open-source degrades to the original mode).
	MultiProtocol bool `json:"multi_protocol"`
}

// UpstreamProxyGet serves GET /admin/upstream-proxy — the live egress proxy URL the
// local web "Settings → Upstream proxy" card reads to prefill, plus (when wired)
// the layered egress decision for `aikey env`. 503 if not wired.
func (h *Handler) UpstreamProxyGet(w http.ResponseWriter, _ *http.Request) {
	if h.GetUpstreamProxyFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "upstream-proxy config not supported"})
		return
	}
	body := upstreamProxyBody{URL: h.GetUpstreamProxyFn()}
	if h.EgressStateFn != nil {
		st := h.EgressStateFn()
		body.Egress = &st
	}
	writeJSON(w, http.StatusOK, body)
}

// UpstreamProxySet serves PUT /admin/upstream-proxy. Validates the URL, persists it
// to aikey-user.yaml, and HOT-SWAPS the running transport + impersonate client via
// SetUpstreamProxyFn (no restart). Empty url clears the proxy (direct egress).
//
// 400 on an invalid URL (bad scheme / missing host:port), 503 if not wired, 500 if
// the persist/hot-swap fails. The body that succeeds echoes the applied url so the
// caller can confirm.
func (h *Handler) UpstreamProxySet(w http.ResponseWriter, r *http.Request) {
	tc := observability.ExtractOrCreate(r)
	logger := slog.With("trace_id", tc.TraceID, "request_id", tc.RequestID)

	if h.SetUpstreamProxyFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "upstream-proxy config not supported"})
		return
	}

	var body upstreamProxyBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := config.ValidateUpstreamProxyURL(body.URL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := h.SetUpstreamProxyFn(body.URL); err != nil {
		logger.Error("admin: upstream-proxy update failed", "error.message", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	logger.Info("admin: upstream-proxy updated + hot-swapped",
		"event.name", "proxy.upstream_proxy.updated", "has_value", body.URL != "")
	writeJSON(w, http.StatusOK, upstreamProxyBody{URL: body.URL})
}

// oauthEgressOverrideBody is the GET/PUT /admin/oauth-egress-override wire shape.
type oauthEgressOverrideBody struct {
	Enabled bool `json:"enabled"`
}

// OAuthEgressOverrideGet serves GET /admin/oauth-egress-override — the live
// escape-hatch state for the Settings checkbox. 503 if not wired (older build).
func (h *Handler) OAuthEgressOverrideGet(w http.ResponseWriter, _ *http.Request) {
	if h.GetOAuthEgressOverrideFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "oauth-egress-override not supported"})
		return
	}
	writeJSON(w, http.StatusOK, oauthEgressOverrideBody{Enabled: h.GetOAuthEgressOverrideFn()})
}

// OAuthEgressOverrideSet serves PUT /admin/oauth-egress-override. Persists the
// flag to aikey-user.yaml and hot-applies it across generations (no restart).
// No spec to validate — a bool. 503 if not wired, 500 if persist/apply fails.
func (h *Handler) OAuthEgressOverrideSet(w http.ResponseWriter, r *http.Request) {
	tc := observability.ExtractOrCreate(r)
	logger := slog.With("trace_id", tc.TraceID, "request_id", tc.RequestID)

	if h.SetOAuthEgressOverrideFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "oauth-egress-override not supported"})
		return
	}
	var body oauthEgressOverrideBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := h.SetOAuthEgressOverrideFn(body.Enabled); err != nil {
		logger.Error("admin: oauth-egress-override update failed", "error.message", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	logger.Info("admin: oauth-egress-override updated + hot-applied",
		"event.name", "proxy.egress.oauth_override_set", "enabled", body.Enabled)
	writeJSON(w, http.StatusOK, oauthEgressOverrideBody{Enabled: body.Enabled})
}

// upstreamProbeResult is the POST /admin/upstream-proxy/probe response. Ok=true with
// a Status means the candidate proxy carried a request through to the provider (any
// HTTP status counts as reachable — auth/404 still proves the tunnel works). Ok=false
// with Error means no response came back (proxy down / DNS / timeout).
type upstreamProbeResult struct {
	Ok        bool   `json:"ok"`
	Status    int    `json:"status,omitempty"`
	ElapsedMs int64  `json:"elapsed_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// UpstreamProxyProbe serves POST /admin/upstream-proxy/probe: tests a CANDIDATE egress
// URL (from the body) end-to-end to an AI provider WITHOUT saving it, so the web can
// verify connectivity before Save. 400 on an invalid URL, 503 if not wired. A probe
// that runs but can't reach the provider is a 200 with ok=false (not an HTTP error) —
// the caller renders it as a "unreachable" result, same shape as a success.
func (h *Handler) UpstreamProxyProbe(w http.ResponseWriter, r *http.Request) {
	if h.ProbeUpstreamProxyFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "upstream-proxy probe not supported"})
		return
	}
	var body upstreamProxyBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := config.ValidateUpstreamProxyURL(body.URL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	status, elapsedMs, err := h.ProbeUpstreamProxyFn(body.URL)
	if err != nil {
		writeJSON(w, http.StatusOK, upstreamProbeResult{Ok: false, ElapsedMs: elapsedMs, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, upstreamProbeResult{Ok: true, Status: status, ElapsedMs: elapsedMs})
}
