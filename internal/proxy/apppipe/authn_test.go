package apppipe

// AKL-204 — Authenticate / extractBearer tests.
//
// We test against a stub headerMap (vs net/http.Request) because the
// extractor + Authenticate only need a `Get(name) string` surface; this
// keeps tests fast and avoids carrying http.Request lifecycle hazards
// (body close, context, etc.) into table-driven cases.

import (
	"net/http"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// headerMap is a tiny stub satisfying requestHeaders for tests.
type headerMap map[string]string

func (m headerMap) Get(name string) string { return m[name] }

// Strict app bearers for fixture work — 74 chars (aikey_app_ + 64-hex).
const (
	bearerAgentA = "aikey_app_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bearerAgentB = "aikey_app_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	bearerPerson = "aikey_personal_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// seededRegistry returns a Registry pre-populated with one app route for
// "agent-a" (bound to bearerAgentA), one for "agent-b" (bearerAgentB),
// and one personal route (bearerPerson) — covers the same shapes
// supervisor.loadVaultRoutesIntoRegistry produces in production.
func seededRegistry() *vkeys.Registry {
	r := vkeys.NewRegistry()
	r.Merge(map[string]*vkeys.ResolvedRoute{
		bearerAgentA: {
			VirtualKeyID: "app:agent-a",
			RouteSource:  "app",
			AppSlug:      "agent-a",
			AppKind:      "third-party",
			AppKeyID:     "uuid-a",
		},
		bearerAgentB: {
			VirtualKeyID:     "app:agent-b",
			RouteSource:      "app",
			AppSlug:          "agent-b",
			AppKind:          "first-party",
			AppKeyID:         "uuid-b",
			FollowUserActive: true,
		},
		bearerPerson: {
			VirtualKeyID: "personal:alice",
			RouteSource:  "personal",
			Provider:     "anthropic",
			KeyAlias:     "alice",
		},
	})
	return r
}

// ---------------------------------------------------------------------------
// extractBearer — both header forms, edge cases.
// ---------------------------------------------------------------------------

func TestExtractBearer_AuthorizationBearer(t *testing.T) {
	got := extractBearer(headerMap{"Authorization": "Bearer " + bearerAgentA})
	if got != bearerAgentA {
		t.Errorf("got %q, want %q", got, bearerAgentA)
	}
}

func TestExtractBearer_XAPIKey(t *testing.T) {
	// Anthropic-style header form — apppipe must accept it for the
	// Anthropic SDK ("@anthropic-ai/sdk", which sets x-api-key by default).
	got := extractBearer(headerMap{"x-api-key": bearerAgentA})
	if got != bearerAgentA {
		t.Errorf("got %q, want %q", got, bearerAgentA)
	}
}

func TestExtractBearer_AuthorizationTakesPrecedence(t *testing.T) {
	// Both headers present: Authorization wins (mirrors proxy.extractVirtualKey).
	got := extractBearer(headerMap{
		"Authorization": "Bearer " + bearerAgentA,
		"x-api-key":     bearerAgentB,
	})
	if got != bearerAgentA {
		t.Errorf("Authorization header should win when both present; got %q", got)
	}
}

func TestExtractBearer_EmptyOrMalformed(t *testing.T) {
	cases := []struct {
		name    string
		headers headerMap
	}{
		{"no headers", headerMap{}},
		{"empty Authorization", headerMap{"Authorization": ""}},
		{"no Bearer prefix", headerMap{"Authorization": bearerAgentA}},
		{"Bearer but empty token", headerMap{"Authorization": "Bearer "}},
		{"Bearer with whitespace only", headerMap{"Authorization": "Bearer    "}},
		{"empty x-api-key", headerMap{"x-api-key": ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractBearer(c.headers); got != "" {
				t.Errorf("expected empty, got %q", got)
			}
		})
	}
}

func TestExtractBearer_TrimsWhitespace(t *testing.T) {
	if got := extractBearer(headerMap{"Authorization": "Bearer " + bearerAgentA + "  "}); got != bearerAgentA {
		t.Errorf("expected trimmed, got %q", got)
	}
	if got := extractBearer(headerMap{"x-api-key": "  " + bearerAgentA + "\n"}); got != bearerAgentA {
		t.Errorf("expected trimmed, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Authenticate — happy path.
// ---------------------------------------------------------------------------

func TestAuthenticate_HappyPath(t *testing.T) {
	registry := seededRegistry()
	appCtx := &AppContext{Slug: "agent-a", StrippedPath: "/chat"}

	route, authErr := Authenticate(
		headerMap{"Authorization": "Bearer " + bearerAgentA},
		registry,
		appCtx,
	)
	if authErr != nil {
		t.Fatalf("expected nil error, got %+v", authErr)
	}
	if route == nil {
		t.Fatal("expected non-nil route")
	}
	if route.AppSlug != "agent-a" {
		t.Errorf("AppSlug = %q, want agent-a", route.AppSlug)
	}
	if route.AppKeyID != "uuid-a" {
		t.Errorf("AppKeyID = %q, want uuid-a", route.AppKeyID)
	}
}

// ---------------------------------------------------------------------------
// Authenticate — failure modes (each error code is documented in the
// authn.go docstring; tests pin status code + error code + a meaningful
// fragment of the user-facing message).
// ---------------------------------------------------------------------------

func TestAuthenticate_MissingBearerReturnsTokenMissing(t *testing.T) {
	registry := seededRegistry()
	appCtx := &AppContext{Slug: "agent-a"}

	route, authErr := Authenticate(headerMap{}, registry, appCtx)
	if route != nil {
		t.Errorf("expected nil route on missing bearer, got %+v", route)
	}
	if authErr == nil {
		t.Fatal("expected non-nil AuthError")
	}
	if authErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", authErr.StatusCode)
	}
	if authErr.ErrorCode != "TOKEN_MISSING" {
		t.Errorf("ErrorCode = %q, want TOKEN_MISSING", authErr.ErrorCode)
	}
}

func TestAuthenticate_UnknownTokenReturnsAppKeyNotFound(t *testing.T) {
	registry := seededRegistry()
	appCtx := &AppContext{Slug: "agent-a"}

	// Token that's well-formed but never registered.
	unknown := "aikey_app_dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	route, authErr := Authenticate(
		headerMap{"Authorization": "Bearer " + unknown},
		registry,
		appCtx,
	)
	if route != nil {
		t.Errorf("expected nil route on unknown token, got %+v", route)
	}
	if authErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", authErr.StatusCode)
	}
	if authErr.ErrorCode != "APP_KEY_NOT_FOUND" {
		t.Errorf("ErrorCode = %q, want APP_KEY_NOT_FOUND", authErr.ErrorCode)
	}
}

func TestAuthenticate_NonAppTokenReturnsAppTokenRequired(t *testing.T) {
	// User pasted a personal token (RouteSource="personal") into the
	// /apps/ URL — mirror image of AKL-208's APP_TOKEN_WRONG_PATH.
	registry := seededRegistry()
	appCtx := &AppContext{Slug: "agent-a"}

	route, authErr := Authenticate(
		headerMap{"Authorization": "Bearer " + bearerPerson},
		registry,
		appCtx,
	)
	if route != nil {
		t.Errorf("expected nil route, got %+v", route)
	}
	if authErr.ErrorCode != "APP_TOKEN_REQUIRED" {
		t.Errorf("ErrorCode = %q, want APP_TOKEN_REQUIRED", authErr.ErrorCode)
	}
	// Message should mention what kind of token they sent so they can
	// trace back to where it came from.
	if !containsAll(authErr.Message, "personal", "agent-a") {
		t.Errorf("message missing diagnostic detail: %s", authErr.Message)
	}
}

func TestAuthenticate_WrongSlugReturnsAppMismatch(t *testing.T) {
	// Cross-slug token reuse — user has bearerAgentB (issued for
	// agent-b) but is hitting /apps/agent-a/openai/v1/... URL.
	// Security-sensitive: returns 403 (not 401) since the token IS
	// valid, just not authorized for THIS slug.
	registry := seededRegistry()
	appCtx := &AppContext{Slug: "agent-a"}

	route, authErr := Authenticate(
		headerMap{"Authorization": "Bearer " + bearerAgentB},
		registry,
		appCtx,
	)
	if route != nil {
		t.Errorf("expected nil route on slug mismatch, got %+v", route)
	}
	if authErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403 (token valid, just unauthorized for this slug)", authErr.StatusCode)
	}
	if authErr.ErrorCode != "APP_MISMATCH" {
		t.Errorf("ErrorCode = %q, want APP_MISMATCH", authErr.ErrorCode)
	}
	// Message should name BOTH slugs so the user can spot which side is wrong.
	if !containsAll(authErr.Message, "agent-b", "agent-a") {
		t.Errorf("message must name both slugs (token's vs URL's): %s", authErr.Message)
	}
}

func TestAuthenticate_NilRegistryReturnsServerError(t *testing.T) {
	// Defensive — caller mishap (registry not wired in test / startup
	// race). Should NOT panic. Returns 503 to differentiate from
	// user-side failures.
	appCtx := &AppContext{Slug: "agent-a"}
	route, authErr := Authenticate(
		headerMap{"Authorization": "Bearer " + bearerAgentA},
		nil,
		appCtx,
	)
	if route != nil {
		t.Errorf("expected nil route, got %+v", route)
	}
	if authErr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("StatusCode = %d, want 503 (server-side wiring issue)", authErr.StatusCode)
	}
	if authErr.ErrorCode != "REGISTRY_NOT_AVAILABLE" {
		t.Errorf("ErrorCode = %q, want REGISTRY_NOT_AVAILABLE", authErr.ErrorCode)
	}
}

// containsAll returns true iff every needle is present in haystack.
// Tiny helper for asserting multiple substrings in user-facing error
// messages without writing 5 separate strings.Contains lines per test.
func containsAll(haystack string, needles ...string) bool {
	for _, n := range needles {
		if !contains(haystack, n) {
			return false
		}
	}
	return true
}

func contains(haystack, needle string) bool {
	// Defer to strings.Contains via a re-import is overkill; this 4-line
	// version keeps the test file's import list minimal.
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
