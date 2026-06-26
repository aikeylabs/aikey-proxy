package proxy

// N8b integration tests: a group VK presented at the legacy /v1 entry is
// resolved (N8a) + injected + forwarded. Uses capturingTransport (defined in
// oauth_binding_fence_test.go) to observe the outbound URL + headers without
// touching the network, and encMat/grKey (group_resolve_test.go) to build the
// encrypted at-rest material.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// fakeGroupKey provides the derived key for at-rest group material decryption.
type fakeGroupKey struct{ k []byte }

func (f fakeGroupKey) DerivedKey() []byte { return f.k }

// outboundCapture records the OUTBOUND (post-Director) request — the clone the
// upstream would see. api_key injection (prov.RewriteRequest) happens in the
// Director on this clone, so the original inbound r.Header would not show it;
// asserting on the outbound request is the correct semantics.
type outboundCapture struct {
	host        string
	auth        string
	apiKey      string
	session     string
	stainlessOS string
	// status (0 → 200) + respHeader let a test simulate an upstream failure for
	// the N8c cooldown path.
	status     int
	respHeader http.Header
}

func (c *outboundCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	c.host = req.URL.Host
	c.auth = req.Header.Get("Authorization")
	c.apiKey = req.Header.Get("x-api-key")
	c.session = req.Header.Get("X-Claude-Code-Session-Id")
	c.stainlessOS = req.Header.Get("X-Stainless-OS")
	st := c.status
	if st == 0 {
		st = 200
	}
	h := http.Header{"Content-Type": []string{"application/json"}}
	for k, v := range c.respHeader {
		h[k] = v
	}
	return &http.Response{
		StatusCode: st,
		Header:     h,
		Body: io.NopCloser(strings.NewReader(
			`{"id":"msg","type":"message","content":[{"type":"text","text":"ok"}],"model":"c","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)),
		Request: req,
	}, nil
}

// setupGroupProxy seeds one group VK route + wires the key provider + the
// outbound-capturing transport, returning the capture for assertions.
func setupGroupProxy(t *testing.T, key []byte, route *vkeys.ResolvedRoute) (*Proxy, *outboundCapture) {
	t.Helper()
	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_grouptest": route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	tr := &outboundCapture{}
	p.SetTransport(tr)
	return p, tr
}

func groupReq(body string) (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_grouptest")
	return req, httptest.NewRecorder()
}

const groupBody = `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`

func TestGroupServe_OAuthAccountInjectsBearer(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-1",
		}, "oauth-tok-live"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("group OAuth route: status=%d body=%s", w.Code, w.Body.String())
	}
	// OAuth → providerDefaultBaseURL(anthropic), Bearer injected, x-api-key gone.
	if tr.host != "api.anthropic.com" {
		t.Fatalf("outbound host=%q want api.anthropic.com", tr.host)
	}
	if tr.auth != "Bearer oauth-tok-live" {
		t.Fatalf("outbound Authorization=%q want decrypted OAuth Bearer (oauthInject must run)", tr.auth)
	}
	if tr.apiKey != "" {
		t.Fatalf("x-api-key must be stripped on OAuth path, got %q", tr.apiKey)
	}
}

// Regression (live full-pipeline E2E 2026-06-25): a REAL group VK has an EMPTY
// VK-level ProviderCode/Provider — it's bound to a oauth_group, not a provider,
// so the provider lives per-account in group_accounts. The serve path must take
// the provider from the RESOLVED account, not the route, or canonicalCode=""
// yields an empty upstream base URL → 502. (handleOauthGroupRoute originally used
// rc.ProviderCode; hermetic tests set route.ProviderCode so never hit the empty
// case — only the live pipeline did.)
func TestGroupServe_EmptyRouteProviderUsesAccountProvider(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}} // provider only on the candidate
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-1",
		}, "oauth-tok-live"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", ProtocolType: "anthropic", RouteSource: "team",
		// Provider + ProviderCode intentionally EMPTY — the real group-VK shape.
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("empty-ProviderCode group route: status=%d body=%s", w.Code, w.Body.String())
	}
	// Provider must come from the resolved account → real upstream + Bearer injected.
	if tr.host != "api.anthropic.com" {
		t.Fatalf("outbound host=%q want api.anthropic.com (provider must come from the resolved account, not the empty route)", tr.host)
	}
	if tr.auth != "Bearer oauth-tok-live" {
		t.Fatalf("outbound Authorization=%q want OAuth Bearer", tr.auth)
	}
}

func TestGroupServe_APIKeyAccountInjectsKey(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-k", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-k": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "api_key", BaseURL: "https://key-upstream.example",
		}, "sk-group-key"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("group api_key route: status=%d body=%s", w.Code, w.Body.String())
	}
	// api_key → upstream is the account's base_url, key injected via adapter.
	if tr.host != "key-upstream.example" {
		t.Fatalf("outbound host=%q want key-upstream.example (api_key base_url)", tr.host)
	}
	if tr.apiKey != "sk-group-key" {
		t.Fatalf("outbound x-api-key=%q want injected group key", tr.apiKey)
	}
}

func TestGroupServe_NoMaterialDegrades503(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: "", // not pulled yet
	}
	p, tr := setupGroupProxy(t, key, route)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no material should degrade 503, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "GROUP_NO_MATERIAL") {
		t.Fatalf("degrade body should carry GROUP_NO_MATERIAL code: %s", w.Body.String())
	}
	if tr.host != "" {
		t.Fatalf("degraded request must NOT reach upstream, dialed %q", tr.host)
	}
}

// NP-4: pool identity disguise is applied to the OUTBOUND request only. The
// inbound r keeps the real employee session/OS so our usage + conversation-audit
// + filter-cache attribute the real conversation (no cross-employee tangling in
// OUR records); Anthropic sees the per-account normalized identity.
func TestGroupServe_PoolPersonaUpstreamOnly(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-pool", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-pool": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-pool",
		}, "tok-pool"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)

	req, w := groupReq(groupBody)
	req.Header.Set("X-Claude-Code-Session-Id", "REAL-SESSION") // a real employee session
	req.Header.Set("X-Stainless-OS", "Windows")
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	// Upstream (outbound clone) → disguised to the account's persona.
	if tr.session == "" || tr.session == "REAL-SESSION" {
		t.Fatalf("upstream session must be normalized, got %q", tr.session)
	}
	if want := personaForAccount("acc-pool").os; tr.stainlessOS != want {
		t.Fatalf("upstream OS=%q want persona %q", tr.stainlessOS, want)
	}
	// Inbound r → real identity preserved (the whole point of NP-4).
	if got := req.Header.Get("X-Claude-Code-Session-Id"); got != "REAL-SESSION" {
		t.Fatalf("inbound r session must stay real for internal attribution, got %q", got)
	}
	if got := req.Header.Get("X-Stainless-OS"); got != "Windows" {
		t.Fatalf("inbound r OS must stay real, got %q", got)
	}
}

// N8c: a pool account whose upstream returns 401 is cooled down, and a later
// request routes around it (here the only candidate → GROUP_ALL_UNUSABLE 503).
func TestGroupServe_CooldownOn401(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-1",
		}, "tok-1"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	tr.status = http.StatusUnauthorized // upstream says the token is broken

	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("first request should forward upstream 401, got %d", w.Code)
	}
	if !p.poolCooldown.skipSet()["acc-1"] {
		t.Fatal("a 401 upstream must cool the account down")
	}

	// Second request: the only candidate is cooling down → no usable account.
	tr.status = 0
	req2, w2 := groupReq(groupBody)
	p.Handle(w2, req2)
	if w2.Code != http.StatusServiceUnavailable || !strings.Contains(w2.Body.String(), "GROUP_ALL_UNUSABLE") {
		t.Fatalf("cooled-down sole account must yield GROUP_ALL_UNUSABLE 503, got %d: %s", w2.Code, w2.Body.String())
	}
}

// N8c discrimination: a WAF business-rejection 429 (no rate-limit signal) must
// NOT cool the account down — it's the request persona, not the account.
func TestGroupServe_NoCooldownOnWAF429(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-1",
		}, "tok-1"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	tr.status = http.StatusTooManyRequests // 429 with NO rate-limit header → WAF

	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("first request should forward the 429, got %d", w.Code)
	}
	if p.poolCooldown.skipSet()["acc-1"] {
		t.Fatal("WAF 429 (no rate-limit signal) must NOT cool the account")
	}
}

// NP-3 fence: the backstop predicate flags exactly the leak case — an OAuth pool
// route forwarded without the disguise stash — and nothing else.
func TestPoolOAuthLacksDisguise_Fence(t *testing.T) {
	grp := &vkeys.ResolvedRoute{OauthGroupID: "grp-1"}
	direct := &vkeys.ResolvedRoute{} // no group
	plainReq := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	stashedReq := stashPoolPersona(httptest.NewRequest(http.MethodPost, "/v1/messages", nil), "acc", "ext")

	// OAuth pool, NOT stashed → the violation the fence exists to catch.
	if !poolOAuthLacksDisguise(grp, oauthSentinelKey, plainReq) {
		t.Fatal("OAuth pool route without stash must be flagged")
	}
	// OAuth pool, stashed → fine (disguise will be applied).
	if poolOAuthLacksDisguise(grp, oauthSentinelKey, stashedReq) {
		t.Fatal("stashed OAuth pool route must not be flagged")
	}
	// api_key pool (realKey is a real key, not the OAuth sentinel) → no persona.
	if poolOAuthLacksDisguise(grp, "sk-real-key", plainReq) {
		t.Fatal("api_key pool route needs no disguise")
	}
	// Non-group route → never flagged.
	if poolOAuthLacksDisguise(direct, oauthSentinelKey, plainReq) {
		t.Fatal("non-group route must not be flagged")
	}
}

// Byte-unchanged guard: a non-group (direct-bind) team route must NOT enter the
// group path — it forwards via the static-key path exactly as before.
func TestGroupServe_DirectBindUnaffected(t *testing.T) {
	key := grKey()
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-direct", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		BaseURL: "https://direct.example", PlaintextKey: "sk-direct-key",
		// OauthGroupID empty → group branch skipped.
	}
	p, tr := setupGroupProxy(t, key, route)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("direct-bind team route: status=%d body=%s", w.Code, w.Body.String())
	}
	if tr.host != "direct.example" {
		t.Fatalf("direct-bind must use its own BaseURL, got %q", tr.host)
	}
	if tr.apiKey != "sk-direct-key" {
		t.Fatalf("direct-bind key injection changed: outbound x-api-key=%q", tr.apiKey)
	}
}

// TestGroupServe_FallbackAttributesToServedAccount verifies the audit/usage
// attribution rule for account switching: when the proxy falls back A→B (account
// A returns 401 and is cooled, account B serves the next request), the RECORDED
// UsageEvent's ACCOUNT attribution must follow the actually-serving account (→B),
// while the USER attribution (VirtualKeyID) stays unchanged. Covers full-test-plan
// §2.2#8 (命中=usage attribution 归账号) + the requirement "切号切审计账号归属、用户归属不变".
//
// Live-event acceptance (e2e-acceptance-live-events): drives two real requests
// through Handle → group resolve → fallback → collector → store, then asserts the
// data the pipeline actually recorded — not just HTTP status.
func TestGroupServe_FallbackAttributesToServedAccount(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-1", ProviderCode: "anthropic"},
		{AccountID: "acc-2", ProviderCode: "anthropic"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-1"}, "tok-1"),
		"acc-2": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-2"}, "tok-2"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	// Map each account's at-rest token back to its account id so we can read the
	// served account off the (synchronous) outbound capture, regardless of which
	// account seatassign picks as rank-0.
	tokToAcct := map[string]string{"tok-1": "acc-1", "tok-2": "acc-2"}

	store := newCapturingStore()
	p := setupTestProxyWithStore(t, "http://unused.invalid", store)
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_grouptest": route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	tr := &outboundCapture{}
	p.SetTransport(tr)

	// Request 1: the primary account serves; upstream 401 cools it down.
	tr.status = http.StatusUnauthorized
	req1, w1 := groupReq(groupBody)
	p.Handle(w1, req1)
	served1 := tokToAcct[strings.TrimPrefix(tr.auth, "Bearer ")]
	if served1 == "" {
		t.Fatalf("req1 outbound auth %q did not map to a known account", tr.auth)
	}
	if !p.poolCooldown.skipSet()[served1] {
		t.Fatalf("401 must cool the serving account %s", served1)
	}

	// Request 2: primary cooling → the proxy switches to the OTHER account.
	tr.status = 0
	req2, w2 := groupReq(groupBody)
	p.Handle(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("fallback request should succeed via the other account, got %d: %s", w2.Code, w2.Body.String())
	}
	served2 := tokToAcct[strings.TrimPrefix(tr.auth, "Bearer ")]
	if served2 == "" || served2 == served1 {
		t.Fatalf("req2 must serve via a DIFFERENT account; served1=%s served2=%s (auth=%q)", served1, served2, tr.auth)
	}

	// AUDIT assertion: poll the recorded events for the 200 (fallback) request and
	// assert account归属 followed the switch while user归属 stayed stable.
	var got events.UsageEvent
	found := false
	for i := 0; i < 500 && !found; i++ {
		store.mu.Lock()
		for j := range store.events {
			if store.events[j].StatusCode == http.StatusOK && store.events[j].AccountID == served2 {
				got = store.events[j]
				found = true
			}
		}
		store.mu.Unlock()
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		t.Fatalf("no 200 usage event attributed to switched-to account %s was recorded", served2)
	}
	// 账号归属 = the account that actually served (B), NOT the cooled primary (A).
	if got.AccountID == served1 {
		t.Fatalf("audit account归属 wrongly stuck on cooled account %s instead of served %s", served1, served2)
	}
	// 用户归属 stable across the switch.
	if got.VirtualKeyID != "vk-grp" {
		t.Fatalf("user归属 must stay stable across switch: VirtualKeyID=%q want vk-grp", got.VirtualKeyID)
	}
}
