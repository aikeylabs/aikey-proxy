package proxy

// Integration tests for the 2026-04-29 namespace-authority principle.
//
// Tests pin the contract: any token starting with `aikey_` is authoritatively
// classified by ClassifyToken. Unknown / malformed forms must return
// HTTP 401 + body.error.code = "TOKEN_INVALID" — NEVER silently fall through
// to default-binding lookup. Native (non-aikey_) tokens still fall through.
//
// Spec: roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md §3
//       roadmap20260320/技术实现/update/20260429-token前缀重命名-e2e测试方案.md §6.2

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hardFailureCases lists every aikey_*-prefixed token form that MUST receive
// TOKEN_INVALID 401 — no silent fallthrough allowed.
var hardFailureCases = []struct {
	name  string
	token string
}{
	// Reserved namespace — not implemented this round.
	{"aikey_route_anything", "aikey_route_anything"},
	{"aikey_route_64hex", "aikey_route_" + strings.Repeat("0", 64)},
	// Unknown subform.
	{"aikey_unknown_xyz", "aikey_unknown_xyz"},
	{"aikey_xyz", "aikey_xyz"},
	// Empty team vk_id.
	{"aikey_team_empty", "aikey_team_"},
	// Legacy aikey_vk_* — fully removed post-migration; must fail loud
	// instead of silently falling back to active binding.
	{"legacy aikey_vk_short", "aikey_vk_short"},
	{"legacy aikey_vk_64hex", "aikey_vk_" + strings.Repeat("0", 64)},
	// Personal bearer with wrong shape.
	{"aikey_personal_63hex", "aikey_personal_" + strings.Repeat("0", 63)},
	{"aikey_personal_65hex", "aikey_personal_" + strings.Repeat("0", 65)},
	{"aikey_personal_uppercase", "aikey_personal_" + strings.Repeat("A", 64)},
	{"aikey_personal_nonhex_g", "aikey_personal_" + strings.Repeat("g", 64)},
	{"aikey_personal_empty_suffix", "aikey_personal_"},
	// Legacy personal sentinel forms (alias / UUID after `aikey_personal_`).
	{"legacy personal alias", "aikey_personal_my-claude"},
	{"legacy personal UUID", "aikey_personal_54f8a3e1-b4d9-4e21-9fa0-0e3c5b7d8a91"},
}

// TestNamespaceAuthority_HardFailureForAikeyPrefix sends each malformed
// aikey_*-prefixed token through the proxy via path-prefix routing and
// asserts TOKEN_INVALID, NOT silent fallthrough.
func TestNamespaceAuthority_HardFailureForAikeyPrefix(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the request reaches upstream, the proxy silently fell through —
		// that's a violation of the namespace-authority principle.
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)

	for _, c := range hardFailureCases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+c.token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			p.Handle(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("token %q: expected HTTP 401, got %d (body=%s)",
					c.token, resp.StatusCode, rec.Body.String())
				return
			}
			if !strings.Contains(rec.Body.String(), "TOKEN_INVALID") {
				t.Errorf("token %q: response body must contain TOKEN_INVALID, got: %s",
					c.token, rec.Body.String())
			}
		})
	}
}

// TestNamespaceAuthority_ActiveSentinelFallsThroughIntentionally pins the
// SOLE exception within the aikey_* namespace allowed to fall through. The
// active sentinel is by-design dependent on tier-3's path-binding lookup.
//
// We don't fully exercise the binding lookup here (would require a real
// vault); we only verify the sentinel is NOT classified as TokenInvalid by
// ClassifyToken — which means the dispatch will let it fall through to the
// binding-resolution path instead of hard-failing.
func TestNamespaceAuthority_ActiveSentinelNotClassifiedAsInvalid(t *testing.T) {
	cases := []string{
		"aikey_active_anthropic",
		"aikey_active_openai",
		"aikey_active_",                    // empty provider — still falls through; binding lookup will resolve via path
		"aikey_active_unknown_provider",    // suffix is informational; not validated
	}
	for _, tok := range cases {
		if got := ClassifyToken(tok); got != Tier3ActiveSentinel {
			t.Errorf("ClassifyToken(%q) = %v, want Tier3ActiveSentinel "+
				"(active sentinel is the SOLE aikey_* form allowed to fall through)",
				tok, got)
		}
	}
}

// TestNamespaceAuthority_NativeTokensFallthrough pins that non-aikey_
// tokens (native upstream credentials sent by CLI tools like Cursor,
// claude, etc.) continue to fall through to the path-binding lookup as
// before — namespace authority applies ONLY to aikey_* prefixed tokens.
func TestNamespaceAuthority_NativeTokensClassifiedAsTier3Native(t *testing.T) {
	cases := []string{
		"sk-1234567890",
		"sk-ant-real-secret",
		"abc-random",
		"aikeyfoo",  // edge: starts with "aikey" but no underscore — NOT in the namespace
		"",
	}
	for _, tok := range cases {
		if got := ClassifyToken(tok); got != Tier3Native {
			t.Errorf("ClassifyToken(%q) = %v, want Tier3Native "+
				"(non-aikey_ tokens must NOT trigger namespace-authority hard-fail)",
				tok, got)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Legacy /v1/... entry — namespace authority gate (review #1, 2026-04-29)
// ─────────────────────────────────────────────────────────────────────
//
// Pins that the non-path-prefix entry path also enforces namespace
// authority. The original implementation skipped ClassifyToken at this
// entry, which would let `aikey_route_*` / malformed `aikey_personal_*`
// slip through to Registry.Resolve and produce misleading errors.

func TestLegacyEntry_TokenInvalidHardFails(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)

	for _, c := range hardFailureCases {
		t.Run(c.name, func(t *testing.T) {
			// Legacy entry: NO path prefix.
			req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+c.token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			p.Handle(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("legacy entry token %q: expected HTTP 401, got %d (body=%s)",
					c.token, resp.StatusCode, rec.Body.String())
				return
			}
			if !strings.Contains(rec.Body.String(), "TOKEN_INVALID") {
				t.Errorf("legacy entry token %q: response must contain TOKEN_INVALID, got: %s",
					c.token, rec.Body.String())
			}
		})
	}
}

// Tier3ActiveSentinel and Tier2Probe MUST be rejected at legacy entry —
// they need a path-derived canonical provider to resolve. Returning
// TOKEN_INVALID with a hint to use path-prefix routing is the documented
// behavior.
func TestLegacyEntry_ActiveAndProbeRejectedAsNotApplicable(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)

	cases := []struct {
		name string
		tok  string
	}{
		{"active sentinel", "aikey_active_anthropic"},
		{"probe sentinel", "aikey_probe_my-claude"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+c.tok)
			rec := httptest.NewRecorder()

			p.Handle(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("token %q at legacy entry: expected 401, got %d (body=%s)",
					c.tok, rec.Code, rec.Body.String())
				return
			}
			if !strings.Contains(rec.Body.String(), "path-prefix routing") {
				t.Errorf("token %q at legacy entry: error message must hint path-prefix routing, got: %s",
					c.tok, rec.Body.String())
			}
		})
	}
}
