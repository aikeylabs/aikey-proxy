package proxy

import (
	"net/http"
	"os"
	"strings"
	"sync/atomic"
)

// Upstream-headers debug toggle.
//
// Diagnostic switch that, when enabled, logs the final HTTP method, URL, and
// headers of every request the proxy forwards to an AI provider. Used to
// verify the persona / auth / body-rewrite layers (e.g. confirming Claude
// OAuth's required `User-Agent: claude-cli/...`, `?beta=true`, or
// `metadata.user_id` reach the upstream as intended).
//
// Three resolution layers, most authoritative first:
//
//  1. API runtime override:  POST /admin/debug/upstream-headers
//     Atomic int32, lives in process memory. Once set explicitly to ON or
//     OFF, takes precedence over env and compile. DELETE clears it back to
//     "inherit lower layers".
//
//  2. Environment variable:  AIKEY_PROXY_DEBUG_UPSTREAM_HEADERS
//     Read at request time (cheap getenv) so operators can toggle via
//     EnvironmentFile reload without proxy restart. Empty = inherit compile.
//     Truthy values: "1", "true", "on", "yes" (case-insensitive).
//     Falsy values: "0", "false", "off", "no".
//
//  3. Compile-time default:  compileTimeDebugUpstreamHeaders var
//     Injected via -ldflags "-X
//     github.com/AiKeyLabs/aikey-proxy/internal/proxy.compileTimeDebugUpstreamHeaders=1".
//     Empty (default) = OFF — release builds stay quiet unless an operator
//     deliberately flips at deploy time.
//
// Why default OFF at every layer: persona headers expose internal proxy IDs
// (X-Claude-Code-Session-Id), the OAuth account UUID encoded in
// metadata.user_id, and any client-set fingerprint headers. Logging them
// every request inflates jsonl size and surfaces account UUIDs into
// developer-facing logs. The toggle scopes that exposure to deliberate
// diagnostic windows.

// compileTimeDebugUpstreamHeaders is set by ldflags at build time. Empty
// means "compile-layer says OFF; defer to env / API". Set to "1" / "true"
// / "on" / "yes" to default ON. Build example:
//
//	go build -ldflags "-X github.com/AiKeyLabs/aikey-proxy/internal/proxy.compileTimeDebugUpstreamHeaders=1" ./cmd/aikey-proxy
var compileTimeDebugUpstreamHeaders = ""

// apiDebugUpstreamHeaders is the runtime API override. Accessed via atomic.
//
//	0 = unset (inherit env / compile)
//	1 = explicit ON
//	2 = explicit OFF
//
// Why a separate "OFF" state instead of just "ON or unset": operators may
// want to force-disable at runtime even when env or compile says ON
// (incident response, sudden log volume).
var apiDebugUpstreamHeaders int32

// SetUpstreamHeadersDebugAPIOverride flips the runtime API override.
// state values:
//
//	1  → force ON
//	0  → clear override (inherit env / compile)
//	-1 → force OFF
//
// Stored as int32: 0 unset / 1 on / 2 off (avoids negative-zero ambiguity in
// atomic ops).
func SetUpstreamHeadersDebugAPIOverride(state int) {
	switch {
	case state > 0:
		atomic.StoreInt32(&apiDebugUpstreamHeaders, 1)
	case state < 0:
		atomic.StoreInt32(&apiDebugUpstreamHeaders, 2)
	default:
		atomic.StoreInt32(&apiDebugUpstreamHeaders, 0)
	}
}

// UpstreamHeadersDebugState returns the current resolved state plus the
// source layer so admin endpoints can show which layer won. Layers are
// "api", "env", "compile", or "default".
func UpstreamHeadersDebugState() (enabled bool, source string) {
	switch atomic.LoadInt32(&apiDebugUpstreamHeaders) {
	case 1:
		return true, "api"
	case 2:
		return false, "api"
	}
	if v := os.Getenv("AIKEY_PROXY_DEBUG_UPSTREAM_HEADERS"); v != "" {
		return parseDebugTruthy(v), "env"
	}
	if compileTimeDebugUpstreamHeaders != "" {
		return parseDebugTruthy(compileTimeDebugUpstreamHeaders), "compile"
	}
	return false, "default"
}

// debugUpstreamHeadersEnabled is the hot-path check used by the Director.
// Drops the source string for zero-allocation; admin endpoints use
// UpstreamHeadersDebugState instead.
func debugUpstreamHeadersEnabled() bool {
	switch atomic.LoadInt32(&apiDebugUpstreamHeaders) {
	case 1:
		return true
	case 2:
		return false
	}
	if v := os.Getenv("AIKEY_PROXY_DEBUG_UPSTREAM_HEADERS"); v != "" {
		return parseDebugTruthy(v)
	}
	return parseDebugTruthy(compileTimeDebugUpstreamHeaders)
}

// parseDebugTruthy interprets common boolish strings. Anything else returns
// false (including the empty string), so the caller can pass an unset env
// var or compile var directly.
func parseDebugTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "on", "yes", "enable", "enabled":
		return true
	}
	return false
}

// maskAuthHeaders returns headers as a map[string]string for structured
// logging, with credential-bearing values replaced. Keeps the rest of the
// request fingerprint visible for diagnostic comparison without leaking
// bearer tokens or API keys.
//
// Why mask only Authorization and x-api-key: those are the only fields
// proxy ever stuffs a credential into. Everything else (X-Claude-Code-
// Session-Id, metadata.user_id inside body, OAuth account UUID via persona)
// is internal routing metadata, not a credential — visible in logs is OK
// when the toggle is deliberately on.
func maskAuthHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		switch strings.ToLower(k) {
		case "authorization", "x-api-key":
			out[k] = "<masked>"
		default:
			out[k] = strings.Join(v, ", ")
		}
	}
	return out
}
