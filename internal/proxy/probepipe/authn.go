package probepipe

// authn.go — Bearer token validation for the Probe pipeline.
//
// Per SPEC §1.3, the Probe pipeline accepts only the well-known first-party
// constant Bearer(s). Unlike apppipe.Authenticate which consults the in-memory
// Registry (because app bearers are issued/rotated dynamically by `aikey
// app authorize`), probe bearers are baked-in constants that don't depend on
// vault state — so we check directly against a tiny whitelist here.

import (
	"net/http"
	"strings"
)

// AuthError carries probe-pipeline auth failures with HTTP status + code + message.
type AuthError struct {
	ErrorCode  string // body.error.code — always PROBE_AUTH_FAILED for this pipeline
	Message    string // body.error.message — user-actionable English per CLAUDE.md
	StatusCode int    // HTTP status to return (401 for probe)
}

func (e *AuthError) Error() string { return e.ErrorCode + ": " + e.Message }

// firstPartyAppBearers — the set of internal first-party Bearers allowed to
// invoke /probe/<alias>/.... Mirror of proxy/dispatch.go::firstPartyAppBearerWhitelist;
// duplicated due to import-cycle constraints (probepipe imports vault; proxy
// imports probepipe).
//
// **Drift 防退化**: this map must equal the matching constants in:
//   - aikey-proxy/internal/proxy/dispatch.go::firstPartyAppBearerWhitelist
//   - aikey-proxy/internal/vault/route_token_form.go
//   - aikey-proxy/internal/supervisor/team_token_normalize.go
//   - ai-degrade-detector/server_local/services/check_orchestrator.py::FIRST_PARTY_APP_KEY
//   - aikey-cli/src/migrations.rs::DEGRADE_DETECTOR_FIRST_PARTY_BEARER
//
// SPEC: workflow/CI/requirements/2026-05-23-credential-mode-architecture.md §1.3
// and 2026-05-22-l3-rhythm-signal-design-rules.md §1.3.
var firstPartyAppBearers = map[string]struct{}{
	"aikey_app_internal_degrade_detector_v1": {},
}

// RequestHeaders is the minimal interface Authenticate needs from
// *http.Request. Decoupling lets tests pass a stub.
type RequestHeaders interface {
	Get(name string) string
}

// Authenticate verifies the probe-pipeline Bearer is one of the allowed
// first-party app constants.
//
// Returns nil on success; non-nil AuthError otherwise:
//   - missing Authorization / x-api-key header → PROBE_AUTH_FAILED 401
//   - bearer not in first-party whitelist      → PROBE_AUTH_FAILED 401
//
// We deliberately collapse both failure modes into a single error code:
// distinguishing them would leak information about which Bearer values are
// valid (timing-side-channel against the whitelist). Operators get the
// precise reason via proxy-side WARN log; clients see only "auth failed".
func Authenticate(h RequestHeaders) *AuthError {
	token := extractBearer(h)
	if token == "" {
		return &AuthError{
			StatusCode: http.StatusUnauthorized,
			ErrorCode:  "PROBE_AUTH_FAILED",
			Message: "Missing bearer token. The Probe pipeline requires the " +
				"first-party constant Bearer in `Authorization: Bearer <token>` " +
				"or `x-api-key: <token>`.",
		}
	}
	if _, ok := firstPartyAppBearers[token]; !ok {
		return &AuthError{
			StatusCode: http.StatusUnauthorized,
			ErrorCode:  "PROBE_AUTH_FAILED",
			Message: "Bearer token not authorized for the Probe pipeline. Only " +
				"first-party app constants are accepted (SPEC 2026-05-23-credential-mode-architecture §1.3).",
		}
	}
	return nil
}

// extractBearer accepts both header forms commonly used by upstream SDKs:
//   - Authorization: Bearer <token>  (OpenAI-style)
//   - x-api-key: <token>             (Anthropic-style)
//
// Mirrors apppipe.extractBearer; kept local to avoid an internal cross-package
// import for a four-line helper.
func extractBearer(h RequestHeaders) string {
	if auth := h.Get("Authorization"); auth != "" {
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return strings.TrimSpace(token)
		}
	}
	if apiKey := h.Get("x-api-key"); apiKey != "" {
		return strings.TrimSpace(apiKey)
	}
	return ""
}
