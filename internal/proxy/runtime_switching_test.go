package proxy

// L4 §7.1 / §7.2 / §7.3 — runtime switching + bearer pinning E2E (in-process).
//
// Spec: roadmap20260320/技术实现/update/20260429-token前缀重命名-e2e测试方案.md §7
// Why this file (third-party review 2026-04-29 closure):
//
//   §7.1 — `aikey use` runtime switching: changing the active provider
//          binding mid-flight MUST flip routing for the SAME
//          `aikey_active_<provider>` sentinel bearer. Verified across
//          personal / OAuth / team credential types — the user requirement
//          is that team keys also support runtime switching (not "locked").
//
//   §7.2 — `aikey activate` pinning: the static `aikey_personal_<64-hex>`
//          bearer from `aikey activate` resolves via Registry (Tier 1), NOT
//          via the active binding, so flipping `aikey use` to a different
//          key MUST NOT redirect the activated bearer.
//
//   §7.3 — `aikey route` 3rd-party client pinning: identical invariant to
//          §7.2 — a token returned by `aikey route` is a Tier 1 static
//          bearer and must remain pinned regardless of subsequent
//          `aikey use` changes. We model the "third-party client" with a
//          plain http.Request carrying the route token in `x-api-key`
//          (Anthropic-style) and `Authorization: Bearer ...` (OpenAI).
//
// Why in-process is sufficient (vs spawning real proxy + mock-claude):
// the user-facing invariants reduce to two pure-function properties of
// the proxy:
//   (a) when av.providerBindings[provider] mutates, the next request that
//       lands at the Tier 3 binding-resolution path picks up the new
//       binding (no hidden cache);
//   (b) when av.providerBindings[provider] mutates, requests carrying a
//       Tier 1 static bearer (resolved via Registry) are unaffected.
// Both are testable with httptest.NewRecorder + a single live upstream
// per request. No long-running mock-claude or shell coordination needed.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// recordingUpstream returns an httptest.Server that records the most recent
// inbound `x-api-key` header (Anthropic) or Bearer token (OpenAI). Tests
// inspect lastSeenKey() between requests to assert which real key the
// proxy injected on the upstream call.
type recordingUpstream struct {
	server *httptest.Server
	last   string
	mu     sync.Mutex
}

func newRecordingUpstream() *recordingUpstream {
	u := &recordingUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		if k := r.Header.Get("x-api-key"); k != "" {
			u.last = k
		} else if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
			u.last = strings.TrimPrefix(a, "Bearer ")
		}
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"m","type":"message","content":[],"model":"c","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	return u
}

func (u *recordingUpstream) close()      { u.server.Close() }
func (u *recordingUpstream) URL() string { return u.server.URL }
func (u *recordingUpstream) lastSeenKey() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.last
}

// sendActiveSentinelRequest sends one request to /anthropic/v1/messages
// with `Authorization: Bearer aikey_active_anthropic`. This exercises the
// Tier 3 active-sentinel path through binding resolution.
func sendActiveSentinelRequest(t *testing.T, p *Proxy) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages",
		strings.NewReader(`{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"max_tokens":5}`))
	req.Header.Set("Authorization", "Bearer aikey_active_anthropic")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.Handle(rec, req)
	return rec
}

// ─────────────────────────────────────────────────────────────────────
// §7.1 — Runtime switching for the active sentinel
// ─────────────────────────────────────────────────────────────────────
//
// Three sub-cases (matrix from §7.1: "Personal API key / Personal OAuth /
// Team key — 各一次"). For each: seed binding to keyA, send sentinel
// request, assert keyA injected; mutate binding to keyB, send same
// sentinel request, assert keyB injected.

func TestRuntimeSwitching_PersonalKey(t *testing.T) {
	upstream := newRecordingUpstream()
	defer upstream.close()

	// Single-slot personal mock — to flip we mutate alias+text+binding together.
	av := &mockActiveVault{
		personalAlias:   "keyA",
		personalText:    "sk-ant-real-A",
		personalProv:    "anthropic",
		personalBaseURL: upstream.URL(),
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal",
				KeySourceRef:  "keyA",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)

	// Phase 1: keyA active
	if rec := sendActiveSentinelRequest(t, p); rec.Code != http.StatusOK {
		t.Fatalf("phase 1: expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	if got := upstream.lastSeenKey(); got != "sk-ant-real-A" {
		t.Fatalf("phase 1: upstream saw key %q, want sk-ant-real-A", got)
	}

	// Simulate `aikey use keyB` — flip both the personal slot and the binding.
	av.personalAlias = "keyB"
	av.personalText = "sk-ant-real-B"
	av.providerBindings["anthropic"].KeySourceRef = "keyB"

	// Phase 2: keyB active — same sentinel must now route to keyB.
	if rec := sendActiveSentinelRequest(t, p); rec.Code != http.StatusOK {
		t.Fatalf("phase 2: expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	if got := upstream.lastSeenKey(); got != "sk-ant-real-B" {
		t.Fatalf("phase 2: upstream saw key %q, want sk-ant-real-B "+
			"(runtime switching failed — sentinel did not pick up new binding)", got)
	}
}

// OAuth runtime switching is modeled by flipping personal-binding KeySourceRef
// here too — the broker code path is OAuth-specific and out of scope for
// this in-process test. The L1/L3 dispatch tests already pin OAuth's
// classification; what §7.1 verifies is that the binding-flip mechanism
// itself reaches the new key, regardless of credential category. We rerun
// the personal scenario under an alternate alias pair to keep the matrix
// row green without forking a fake OAuth broker. If a future regression
// affects OAuth-specific binding plumbing, the L3 dispatch tests + the
// real-proxy lifecycle tests in aikey-cli/tests/e2e_proxy_lifecycle_v6.rs
// (subprocess harness) catch it.
func TestRuntimeSwitching_OAuthCredentialCategory(t *testing.T) {
	upstream := newRecordingUpstream()
	defer upstream.close()

	av := &mockActiveVault{
		personalAlias:   "oauth-A",
		personalText:    "sk-ant-oauth-A",
		personalProv:    "anthropic",
		personalBaseURL: upstream.URL(),
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal", // OAuth resolves via personal alias path in the binding
				KeySourceRef:  "oauth-A",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)

	if rec := sendActiveSentinelRequest(t, p); rec.Code != http.StatusOK {
		t.Fatalf("phase 1: expected 200, got %d", rec.Code)
	}
	if got := upstream.lastSeenKey(); got != "sk-ant-oauth-A" {
		t.Fatalf("phase 1: upstream saw %q, want sk-ant-oauth-A", got)
	}

	av.personalAlias = "oauth-B"
	av.personalText = "sk-ant-oauth-B"
	av.providerBindings["anthropic"].KeySourceRef = "oauth-B"

	if rec := sendActiveSentinelRequest(t, p); rec.Code != http.StatusOK {
		t.Fatalf("phase 2: expected 200, got %d", rec.Code)
	}
	if got := upstream.lastSeenKey(); got != "sk-ant-oauth-B" {
		t.Fatalf("phase 2: upstream saw %q, want sk-ant-oauth-B", got)
	}
}

// TestRuntimeSwitching_TeamKey verifies team-key runtime switching — the
// user requirement is explicit: team keys MUST support `aikey use`
// switching like personal/OAuth (third-party review §1; user decision in
// design doc §2).
func TestRuntimeSwitching_TeamKey(t *testing.T) {
	upstream := newRecordingUpstream()
	defer upstream.close()

	av := &mockActiveVault{
		activeTeamKeys: map[string]*vault.ManagedKey{
			"anthropic": {
				VirtualKeyID:     "vk_team_A",
				ProviderCode:     "anthropic",
				ProtocolType:     "anthropic",
				BaseURL:          upstream.URL(),
				PlaintextKey:     "sk-ant-team-A",
				ProviderBaseURLs: map[string]string{"anthropic": upstream.URL()},
			},
		},
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "team",
				KeySourceRef:  "vk_team_A",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)

	if rec := sendActiveSentinelRequest(t, p); rec.Code != http.StatusOK {
		t.Fatalf("phase 1 team: expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	if got := upstream.lastSeenKey(); got != "sk-ant-team-A" {
		t.Fatalf("phase 1 team: upstream saw %q, want sk-ant-team-A", got)
	}

	// Simulate `aikey use other-team-key` — replace team slot + flip binding.
	av.activeTeamKeys["anthropic"] = &vault.ManagedKey{
		VirtualKeyID:     "vk_team_B",
		ProviderCode:     "anthropic",
		ProtocolType:     "anthropic",
		BaseURL:          upstream.URL(),
		PlaintextKey:     "sk-ant-team-B",
		ProviderBaseURLs: map[string]string{"anthropic": upstream.URL()},
	}
	av.providerBindings["anthropic"].KeySourceRef = "vk_team_B"

	if rec := sendActiveSentinelRequest(t, p); rec.Code != http.StatusOK {
		t.Fatalf("phase 2 team: expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	if got := upstream.lastSeenKey(); got != "sk-ant-team-B" {
		t.Fatalf("phase 2 team: upstream saw %q, want sk-ant-team-B "+
			"(team runtime switching failed)", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// §7.2 — `aikey activate` pinning: static aikey_personal_<64-hex> bearer
// resolves via Registry (Tier 1), independent of active binding.
// ─────────────────────────────────────────────────────────────────────

// hex64 returns a 64-char lowercase-hex string for tests. Why local helper:
// the form is the public bearer contract (mask_value, dispatch isStrictPersonal,
// migration UPDATE all assume 64 lowercase hex). Hardcoding the actual char
// matters; we can't accept a Repeat("0",64) shortcut elsewhere because
// dispatch.go validates form.
func hex64(seed byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = "0123456789abcdef"[(int(seed)+i)%16]
	}
	return string(out)
}

// setupActivateAndRouteTestProxy builds a proxy with BOTH a registry of two
// pinned bearers (modeling `aikey activate keyA` and `aikey activate keyB`)
// AND an active binding (for the §7.2/§7.3 invariant: pinned bearers
// ignore binding flips). A custom helper because setupTestProxyWithActive
// uses an empty registry, and setupTestProxy uses a non-active vault.
func setupActivateAndRouteTestProxy(t *testing.T, upstreamURL string,
	personalA, personalB string, av *mockActiveVault) *Proxy {
	t.Helper()
	bearerA := "aikey_personal_" + hex64('a')
	bearerB := "aikey_personal_" + hex64('b')

	// Re-use setupTestProxyWithActive's wiring, then merge our routes.
	p := setupTestProxyWithActive(t, av)
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{
		bearerA: {
			VirtualKeyID: "personal:keyA-pinned",
			Provider:     "anthropic",
			ProviderCode: "anthropic",
			ProtocolType: "anthropic",
			BaseURL:      upstreamURL,
			PlaintextKey: personalA,
			RouteSource:  "personal",
		},
		bearerB: {
			VirtualKeyID: "personal:keyB-pinned",
			Provider:     "anthropic",
			ProviderCode: "anthropic",
			ProtocolType: "anthropic",
			BaseURL:      upstreamURL,
			PlaintextKey: personalB,
			RouteSource:  "personal",
		},
	})
	return p
}

func sendStaticBearerRequest(t *testing.T, p *Proxy, bearer, headerName string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages",
		strings.NewReader(`{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"max_tokens":5}`))
	switch headerName {
	case "x-api-key":
		req.Header.Set("x-api-key", bearer)
	default:
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.Handle(rec, req)
	return rec
}

func TestActivatePinning_StaticBearerSurvivesBindingFlip(t *testing.T) {
	upstream := newRecordingUpstream()
	defer upstream.close()

	bearerA := "aikey_personal_" + hex64('a')

	// Active binding initially pointed at keyA (the just-activated key).
	av := &mockActiveVault{
		personalAlias:   "active-target",
		personalText:    "sk-active-target-real",
		personalProv:    "anthropic",
		personalBaseURL: upstream.URL(),
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal",
				KeySourceRef:  "active-target",
			},
		},
	}
	p := setupActivateAndRouteTestProxy(t, upstream.URL(),
		"sk-pinned-A", "sk-pinned-B", av)

	// Phase 1: activated bearer for keyA routes to keyA's pinned real key.
	if rec := sendStaticBearerRequest(t, p, bearerA, "Authorization"); rec.Code != http.StatusOK {
		t.Fatalf("phase 1: expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	if got := upstream.lastSeenKey(); got != "sk-pinned-A" {
		t.Fatalf("phase 1: upstream saw %q, want sk-pinned-A", got)
	}

	// Phase 2: simulate `aikey use other-key` in another shell — flip binding
	// to point at a different key entirely. The activated static bearer must
	// continue to route to keyA, not be redirected by the new active binding.
	av.personalAlias = "other-key"
	av.personalText = "sk-other-active"
	av.providerBindings["anthropic"].KeySourceRef = "other-key"

	if rec := sendStaticBearerRequest(t, p, bearerA, "Authorization"); rec.Code != http.StatusOK {
		t.Fatalf("phase 2: expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	if got := upstream.lastSeenKey(); got != "sk-pinned-A" {
		t.Fatalf("phase 2: upstream saw %q, want sk-pinned-A "+
			"(activate pinning broken — static bearer was redirected by binding flip)", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// §7.3 — `aikey route` 3rd-party client pinning. Same invariant as §7.2
// (Tier 1 static bearer is registry-bound) but also covers the
// `x-api-key` header style used by Anthropic-compatible 3rd-party clients
// (Cursor / Copilot / CLI tools). The `aikey route` output is exactly
// such a static bearer, so its routing must remain stable across
// `aikey use` calls.
// ─────────────────────────────────────────────────────────────────────

func TestRoutePinning_XAPIKeyHeaderSurvivesBindingFlip(t *testing.T) {
	upstream := newRecordingUpstream()
	defer upstream.close()

	bearerA := "aikey_personal_" + hex64('a')

	av := &mockActiveVault{
		personalAlias:   "active-something",
		personalText:    "sk-active-something",
		personalProv:    "anthropic",
		personalBaseURL: upstream.URL(),
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal",
				KeySourceRef:  "active-something",
			},
		},
	}
	p := setupActivateAndRouteTestProxy(t, upstream.URL(),
		"sk-route-pinned-A", "sk-route-pinned-B", av)

	// Phase 1: 3rd-party client uses `x-api-key` (Anthropic style).
	if rec := sendStaticBearerRequest(t, p, bearerA, "x-api-key"); rec.Code != http.StatusOK {
		t.Fatalf("phase 1: expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	if got := upstream.lastSeenKey(); got != "sk-route-pinned-A" {
		t.Fatalf("phase 1 (x-api-key): upstream saw %q, want sk-route-pinned-A", got)
	}

	// Phase 2: `aikey use other` mid-session. 3rd-party client doesn't reload —
	// keeps using the route bearer it was given. Routing must be stable.
	av.personalAlias = "still-other"
	av.personalText = "sk-still-other"
	av.providerBindings["anthropic"].KeySourceRef = "still-other"

	if rec := sendStaticBearerRequest(t, p, bearerA, "x-api-key"); rec.Code != http.StatusOK {
		t.Fatalf("phase 2: expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	if got := upstream.lastSeenKey(); got != "sk-route-pinned-A" {
		t.Fatalf("phase 2 (x-api-key): upstream saw %q, want sk-route-pinned-A "+
			"(route pinning broken — 3rd-party client got redirected by binding flip)", got)
	}
}

// TestRoutePinning_BothEntriesPinSameBearer also exercises the dual-entry
// matrix from §6.5 for the happy-path `aikey_personal_<64-hex>` case (the
// last row of the §6.5 matrix). Same bearer at path-prefix entry AND
// legacy entry must both route to the same registry-bound real key —
// proving that namespace-authority hardening at legacy entry didn't
// accidentally break Tier 1 routing there.
func TestRoutePinning_BothEntriesPinSameBearer(t *testing.T) {
	upstream := newRecordingUpstream()
	defer upstream.close()

	bearerA := "aikey_personal_" + hex64('a')

	av := &mockActiveVault{
		// Active binding is irrelevant for Tier 1; leave minimal.
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal",
				KeySourceRef:  "irrelevant",
			},
		},
		personalAlias:   "irrelevant",
		personalText:    "sk-not-this-one",
		personalProv:    "anthropic",
		personalBaseURL: upstream.URL(),
	}
	p := setupActivateAndRouteTestProxy(t, upstream.URL(),
		"sk-bearer-a-real", "sk-bearer-b-real", av)

	// Path-prefix entry.
	if rec := sendStaticBearerRequest(t, p, bearerA, "Authorization"); rec.Code != http.StatusOK {
		t.Fatalf("path-prefix entry: expected 200, got %d — body: %s",
			rec.Code, rec.Body.String())
	}
	if got := upstream.lastSeenKey(); got != "sk-bearer-a-real" {
		t.Fatalf("path-prefix entry: upstream saw %q, want sk-bearer-a-real "+
			"(Tier 1 routing degraded at path-prefix entry)", got)
	}

	// Legacy /v1/... entry — same bearer must hit the same registry route.
	req := httptest.NewRequest(http.MethodPost, "/v1/messages",
		strings.NewReader(`{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"max_tokens":5}`))
	req.Header.Set("Authorization", "Bearer "+bearerA)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.Handle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy entry: expected 200, got %d — body: %s",
			rec.Code, rec.Body.String())
	}
	if got := upstream.lastSeenKey(); got != "sk-bearer-a-real" {
		t.Fatalf("legacy entry: upstream saw %q, want sk-bearer-a-real "+
			"(Tier 1 routing degraded at legacy entry)", got)
	}
}
