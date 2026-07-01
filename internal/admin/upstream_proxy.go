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
}

// UpstreamProxyGet serves GET /admin/upstream-proxy — the live egress proxy URL the
// local web "Settings → Upstream proxy" card reads to prefill. 503 if not wired.
func (h *Handler) UpstreamProxyGet(w http.ResponseWriter, _ *http.Request) {
	if h.GetUpstreamProxyFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "upstream-proxy config not supported"})
		return
	}
	writeJSON(w, http.StatusOK, upstreamProxyBody{URL: h.GetUpstreamProxyFn()})
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
