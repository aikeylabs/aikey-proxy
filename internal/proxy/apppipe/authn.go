package apppipe

// authn.go — Bearer token validation for the App pipeline.
//
// Pipeline stage placement: router.go has produced an AppContext from
// the URL; authn.go now verifies the request's bearer token is a
// well-known app key whose vault-recorded AppSlug matches the URL.
// On success, returns the *vkeys.ResolvedRoute from the in-memory
// Registry. On any failure, returns an AuthError carrying the precise
// HTTP status + error code + user-actionable message that the caller
// (proxy.handleAppPipeline) can render as JSON without further mapping.
//
// What this layer does NOT do:
//   - Provider-binding lookup (lives in resolve.go, AKL-205)
//   - Protocol-set membership check (also resolve.go)
//   - Body sanitization / forwarding (egress.go / pipeline.go)
//
// Why structured AuthError vs sentinel errors: HTTP layers downstream
// (the handler) need three coupled values — status code + error code +
// message — and Go's errors.Is/errors.As dance on sentinels would have
// to map each sentinel to the same triple at the call site. A single
// struct keeps the mapping in this file where the contract is defined.

import (
	"net/http"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// AuthError represents a request that failed App pipeline authentication.
// The handler passes StatusCode + ErrorCode + Message straight to
// writeJSONError; the caller does NOT need to know the structure of
// authn's internal failure modes.
type AuthError struct {
	ErrorCode  string // body.error.code (matches the codes documented in 主方案 §11.E)
	Message    string // body.error.message (user-actionable; English per CLAUDE.md)
	StatusCode int    // HTTP status to return (401 or 403)
}

func (e *AuthError) Error() string { return e.ErrorCode + ": " + e.Message }

// extractBearer reads the bearer token from the request, accepting both
// header forms third-party Agents commonly use:
//   - Authorization: Bearer <token>  (OpenAI-style SDKs)
//   - x-api-key: <token>             (Anthropic-style SDKs)
//
// Returns "" if neither header is present. Unlike proxy.extractVirtualKey,
// this returns ANY token shape; the strict `aikey_app_*` form check is
// performed by Authenticate via Registry.Resolve lookup (which only
// contains strict-form bearers post-supervisor-load).
//
// Why duplicate the small extractor from proxy.middleware.go vs importing:
// proxy imports apppipe, not the other way around. Keeping this helper
// local to apppipe avoids an import cycle and mirrors the project pattern
// of small per-package helpers (cf. isStrictPersonalRouteToken duplicated
// in dispatch.go / vault / supervisor).
func extractBearer(r requestHeaders) string {
	if auth := r.Get("Authorization"); auth != "" {
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			token = strings.TrimSpace(token)
			if token != "" {
				return token
			}
		}
	}
	if apiKey := r.Get("x-api-key"); apiKey != "" {
		return strings.TrimSpace(apiKey)
	}
	return ""
}

// requestHeaders is the minimal interface authn.go needs from
// http.Request. Decoupling lets tests pass a stub map without
// constructing a full http.Request just to set 2 headers.
type requestHeaders interface {
	Get(name string) string
}

// Authenticate verifies the incoming bearer for the App pipeline and
// returns the matching ResolvedRoute on success.
//
// Failure modes (each maps to a precise AuthError):
//
//   - TOKEN_MISSING (401)           — no Authorization / x-api-key header at all
//   - APP_KEY_NOT_FOUND (401)       — token not in Registry (Registry holds
//     only strict + active app/personal/oauth
//     bearers, so this catches malformed,
//     revoked, and pre-Phase-4 vault states)
//   - APP_TOKEN_REQUIRED (401)      — token resolves to a personal / team /
//     oauth route, NOT an app route; user
//     presented the wrong token type at the
//     /apps/ URL
//   - APP_MISMATCH (403)            — token resolves to an app route, but
//     the route's AppSlug doesn't match the
//     URL slug — caller pasted the wrong
//     app's token into this URL
//
// Why APP_TOKEN_REQUIRED vs reusing AKL-208's APP_TOKEN_WRONG_PATH: those
// two codes are mirror images — APP_TOKEN_WRONG_PATH is "app token at
// /v1 URL" (AKL-208), this is "non-app token at /apps/ URL". Same family,
// different direction; the messages are user-tailored for each direction.
func Authenticate(headers requestHeaders, registry *vkeys.Registry, appCtx *AppContext) (*vkeys.ResolvedRoute, *AuthError) {
	if registry == nil {
		// Defensive — caller mishap, not a request-side bug. Surface as
		// 500-class so an alert fires, but DON'T leak the nil internals
		// to the user. Returned status 503 because it's a transient
		// server-config issue (Registry not wired); the user shouldn't
		// see this in production.
		return nil, &AuthError{
			StatusCode: http.StatusServiceUnavailable,
			ErrorCode:  "REGISTRY_NOT_AVAILABLE",
			Message:    "Server is not ready (token registry uninitialized). Restart proxy or retry shortly.",
		}
	}

	token := extractBearer(headers)
	if token == "" {
		return nil, &AuthError{
			StatusCode: http.StatusUnauthorized,
			ErrorCode:  "TOKEN_MISSING",
			Message:    "Missing bearer token. Set OPENAI_API_KEY (or x-api-key for Anthropic SDKs) to the value `aikey app authorize <slug>` printed.",
		}
	}

	route := registry.Resolve(token)
	if route == nil {
		// Token genuinely unknown — could be revoked, malformed (filtered
		// at supervisor load), pre-Phase-4 vault residue, or just a typo.
		// We don't distinguish; the resolution failure is the user signal.
		return nil, &AuthError{
			StatusCode: http.StatusUnauthorized,
			ErrorCode:  "APP_KEY_NOT_FOUND",
			Message:    "App bearer token not found. Possible causes: revoked (run `aikey app list`), CLI hasn't bumped vault yet (try restarting proxy), or token mistyped.",
		}
	}

	if route.RouteSource != "app" {
		// Token IS in the registry but it's a personal / team / oauth
		// route. User probably pasted the wrong token into the Agent's
		// env. Suggest the correct command + the /apps/ URL they're
		// currently hitting so they can see the mismatch.
		return nil, &AuthError{
			StatusCode: http.StatusUnauthorized,
			ErrorCode:  "APP_TOKEN_REQUIRED",
			Message:    "This URL requires an app bearer token (aikey_app_<hex>); the token you sent is a " + route.RouteSource + " token. Run `aikey app authorize " + appCtx.Slug + "` to issue an app token for this slug, or use /v1/... if you intended the legacy route.",
		}
	}

	if route.AppSlug != appCtx.Slug {
		// Cross-slug token reuse — security-sensitive failure mode.
		// Return 403 (not 401) because the token IS valid; it's just
		// not authorized for THIS slug.
		return nil, &AuthError{
			StatusCode: http.StatusForbidden,
			ErrorCode:  "APP_MISMATCH",
			Message:    "App bearer token is bound to slug \"" + route.AppSlug + "\" but the URL targets slug \"" + appCtx.Slug + "\". Use the token from `aikey app authorize " + appCtx.Slug + "` for this URL, or change the URL to /apps/" + route.AppSlug + "/<protocol>/v1/...",
		}
	}

	return route, nil
}
