package proxy

// N8b integration tests: a group VK presented at the legacy /v1 entry is
// resolved (N8a) + injected + forwarded. Uses capturingTransport (defined in
// oauth_binding_fence_test.go) to observe the outbound URL + headers without
// touching the network, and encMat/grKey (group_resolve_test.go) to build the
// encrypted at-rest material.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/routingwire"
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
	path        string
	auth        string
	apiKey      string
	session     string
	stainlessOS string
	// status (0 → 200) + respHeader let a test simulate an upstream failure for
	// the N8c cooldown path.
	status     int
	respHeader http.Header
	// N9 failover test hooks: per-Authorization status/error overrides (so one
	// pool account can fail while another serves within the SAME request) and a
	// round-trip counter (asserting how many upstream attempts a request made).
	statusByAuth map[string]int
	errByAuth    map[string]error
	calls        int
	requestIDs   []string
}

func (c *outboundCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls++
	c.host = req.URL.Host
	c.path = req.URL.Path
	c.auth = req.Header.Get("Authorization")
	c.apiKey = req.Header.Get("x-api-key")
	c.session = req.Header.Get("X-Claude-Code-Session-Id")
	c.stainlessOS = req.Header.Get("X-Stainless-OS")
	c.requestIDs = append(c.requestIDs, req.Header.Get("X-Request-Id"))
	if err, ok := c.errByAuth[c.auth]; ok && err != nil {
		return nil, err
	}
	st := c.status
	if s, ok := c.statusByAuth[c.auth]; ok {
		st = s
	}
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
	if tr.path != "/v1/messages" {
		t.Fatalf("outbound path=%q want /v1/messages", tr.path)
	}
	if tr.auth != "Bearer oauth-tok-live" {
		t.Fatalf("outbound Authorization=%q want decrypted OAuth Bearer (oauthInject must run)", tr.auth)
	}
	if tr.apiKey != "" {
		t.Fatalf("x-api-key must be stripped on OAuth path, got %q", tr.apiKey)
	}
}

func TestGroupServe_MockCodexOAuthUsesRuntimeRailAndFingerprintVersion(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{
		AccountID: "acc-mock-codex", ProviderCode: "mock", ProtocolType: "openai_compatible",
	}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-mock-codex": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account",
			ProviderCode:   "mock",
			ProtocolType:   "openai_compatible",
			BaseURL:        "http://127.0.0.1:3000/mock-provider/openai",
			ExpiresAt:      9_000_000_000,
		}, "mock-oauth-token"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", ProtocolType: "openai_compatible", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-mock-codex",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5-codex","input":"hi"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_grouptest")
	w := httptest.NewRecorder()

	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Mock Codex OAuth group route: status=%d body=%s", w.Code, w.Body.String())
	}
	if tr.host != "127.0.0.1:3000" {
		t.Fatalf("outbound host=%q want runtime host 127.0.0.1:3000", tr.host)
	}
	if tr.path != "/mock-provider/openai/v1/responses" {
		t.Fatalf("outbound path=%q want /mock-provider/openai/v1/responses", tr.path)
	}
	if tr.auth != "Bearer mock-oauth-token" {
		t.Fatalf("outbound Authorization=%q want Mock OAuth bearer", tr.auth)
	}
}

func TestGroupServe_MockOAuthMissingBaseURLFailsClosed(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{
		AccountID: "acc-mock", ProviderCode: "mock", ProtocolType: "anthropic",
	}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-mock": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account",
			ProviderCode:   "mock",
			ProtocolType:   "anthropic",
			ExternalID:     "mock-external-id",
			ExpiresAt:      9_000_000_000,
		}, "mock-oauth-token"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", ProtocolType: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-mock",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	req, w := groupReq(groupBody)

	p.Handle(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("missing Mock base URL: status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), observability.ErrCodeProviderError) {
		t.Fatalf("missing Mock base URL must surface provider error: %s", w.Body.String())
	}
	if tr.calls != 0 {
		t.Fatalf("missing Mock base URL must not reach any upstream, calls=%d host=%q", tr.calls, tr.host)
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

// ③ status-code mapping (2026-07-01): the Anthropic SDK retries 5xx/429 with backoff,
// so a PERMANENT failure sent as 503 makes claude hang for minutes. Permanent codes
// must be non-retryable 4xx (fail fast); only genuinely transient ones stay 503.
func TestGroupDegradeStatus(t *testing.T) {
	cases := []struct {
		code       string
		wantStatus int
	}{
		{groupErrNoCandidates, http.StatusForbidden},        // permanent (removed / empty) → fail fast
		{groupErrAllUnusable, http.StatusTooManyRequests},   // rate-limited → 429 (honest)
		{groupErrNoMaterial, http.StatusServiceUnavailable}, // transient sync → retry
		{"SOME_OTHER_CODE", http.StatusServiceUnavailable},  // default transient
	}
	for _, c := range cases {
		got, _ := groupDegradeStatus(c.code)
		if got != c.wantStatus {
			t.Errorf("groupDegradeStatus(%s)=%d want %d", c.code, got, c.wantStatus)
		}
	}
	// The permanent code must NOT be a retryable 5xx (that's the whole bug).
	if s, _ := groupDegradeStatus(groupErrNoCandidates); s >= 500 {
		t.Errorf("NO_CANDIDATES must be a non-retryable 4xx, got %d (5xx → claude backoff-hang)", s)
	}
}

// ② removed-member message fix (2026-06-30): a seat REMOVED from the group gets an
// empty channel-③ delivery — the proxy wipes group_runtime to "{}". The candidate
// snapshot (group_accounts) may still be STALE with entries. This must surface the
// "no available account — contact admin, won't self-resolve" message (NO_CANDIDATES),
// NOT the misleading "credentials still syncing, retry shortly" (NO_MATERIAL) that
// told a removed member to retry forever.
func TestGroupServe_RemovedMemberEmptyMaterialNotSyncing(t *testing.T) {
	key := grKey()
	// Stale snapshot still lists a candidate; material was wiped to "{}".
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: "{}", // pulled → delivered nothing
	}
	p, tr := setupGroupProxy(t, key, route)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	body := w.Body.String()
	// ③ (2026-07-01): a PERMANENT failure must be a NON-retryable 4xx (403), NOT 503.
	// A 503 makes the Anthropic SDK retry with exponential backoff → claude hangs for
	// minutes on a condition that can never succeed (the reported bug), and renders a
	// contradictory "server-side issue, try again" suffix. 403 = fail fast.
	if w.Code != http.StatusForbidden {
		t.Fatalf("removed member (permanent NO_CANDIDATES) must be 403 fail-fast, not %d (503 → claude retry-hang)", w.Code)
	}
	if strings.Contains(body, "GROUP_NO_MATERIAL") || strings.Contains(strings.ToLower(body), "still syncing") {
		t.Fatalf("removed member must NOT get the transient 'still syncing' message: %s", body)
	}
	if !strings.Contains(body, "GROUP_NO_CANDIDATES") {
		t.Fatalf("removed member (empty material) must degrade as NO_CANDIDATES: %s", body)
	}
	if strings.Contains(strings.ToLower(body), "retry") {
		t.Fatalf("removed member must not be told to retry (won't self-resolve): %s", body)
	}
	if tr.host != "" {
		t.Fatalf("degraded request must NOT reach upstream, dialed %q", tr.host)
	}
}

// ① login-prompt producer verification (2026-06-30): a member who has NOT logged
// into the routed pool account (master delivered the account with needs_login=true,
// so group_runtime carries the marker — NON-empty) must get a structured 401
// OAUTH_GROUP_MEMBER_LOGIN_REQUIRED, NOT the 503 "still syncing" degrade. This is the
// user-facing side of the login flow: claude surfaces the proxy's error message, so
// this 401 body IS the "please sign in" prompt. Pairs with the resolver-level
// TestResolveGroup_LoginRequiredNoSkip. Distinguishes login-needed (marker present)
// from not-synced (empty material → TestGroupServe_NoMaterialDegrades503).
func TestGroupServe_LoginRequiredReturns401(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		// needs_login marker carries NO secret — master delivered the account as
		// "member not logged in" (this is what makes material non-empty, so the
		// resolver reaches candNeedsLogin instead of bailing on NO_MATERIAL).
		"acc-1": {CredentialType: "oauth_account", NeedsLogin: true},
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

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("not-logged-in routed account must return 401 login prompt, got %d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(HeaderAikeyErrorSource); got != groupErrLoginRequired {
		t.Fatalf("X-Aikey-Error-Source=%q want %q", got, groupErrLoginRequired)
	}
	body := w.Body.String()
	if !strings.Contains(body, groupErrLoginRequired) {
		t.Fatalf("body must carry the login-required code so the client can act: %s", body)
	}
	if !strings.Contains(body, "acc-1") {
		t.Fatalf("body must name the account to log into: %s", body)
	}
	if !strings.Contains(body, "sign-in") {
		t.Fatalf("body must carry the human sign-in prompt claude will display: %s", body)
	}
	// Must NOT be mistaken for the transient "still syncing" degrade, and must not
	// reach upstream (the request is halted pending login).
	if strings.Contains(body, "GROUP_NO_MATERIAL") {
		t.Fatalf("login-required must NOT be a NO_MATERIAL degrade: %s", body)
	}
	if tr.host != "" {
		t.Fatalf("login-required must not reach upstream, dialed %q", tr.host)
	}
}

// Display contract (20260703 update, spike-verified in dev2): claude only renders
// error.message verbatim for Anthropic-STANDARD error types — the previous custom
// "login_required" type fell into the generic "API error · Retrying" path (11
// blind retries) and the member never saw the sign-in prompt. With console_url
// configured, login_url must be assembled by the PROXY (决策2: single assembly
// point) and appear both as a field and inside the human message.
func TestGroupServe_LoginRequiredDisplayContract(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": {CredentialType: "oauth_account", NeedsLogin: true},
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, _ := setupGroupProxy(t, key, route)
	p.SetConsoleURL("http://127.0.0.1:8090/") // trailing slash must not double up

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		Account  string `json:"account"`
		LoginURL string `json:"login_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("401 body must stay valid JSON: %v — %s", err, w.Body.String())
	}
	if resp.Error.Type != "authentication_error" {
		t.Fatalf("error.type=%q want authentication_error (custom types are NOT rendered by claude)", resp.Error.Type)
	}
	if resp.Error.Code != groupErrLoginRequired {
		t.Fatalf("error.code=%q must keep the precise machine signal %q", resp.Error.Code, groupErrLoginRequired)
	}
	wantURL := "http://127.0.0.1:8090/user/team-oauth"
	if resp.LoginURL != wantURL {
		t.Fatalf("login_url=%q want %q", resp.LoginURL, wantURL)
	}
	if !strings.Contains(resp.Error.Message, wantURL) {
		t.Fatalf("human message must carry the clickable URL (claude shows message only): %s", resp.Error.Message)
	}

	// Bypass statusline hint: the state file must exist with the SAME url
	// (single assembly point) while login is pending...
	statePath := filepath.Join(os.Getenv("AIKEY_RUN_DIR"), "group-login-required.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("state file must be written on login-required 401: %v", err)
	}
	var st struct {
		AccountID string `json:"account_id"`
		LoginURL  string `json:"login_url"`
		WrittenAt int64  `json:"written_at"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("state file must be valid JSON: %v — %s", err, raw)
	}
	if st.AccountID != "acc-1" || st.LoginURL != wantURL || st.WrittenAt == 0 {
		t.Fatalf("state file content mismatch: %+v", st)
	}

	// ...and be CLEARED by the next successful group resolve (member logged in),
	// so statusline recovery is automatic — a stale hint would nag forever.
	mat["acc-1"] = encMat(t, key, vkeys.GroupRuntimeAccount{
		CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-1",
	}, "oauth-tok-live")
	route.GroupRuntime = mustJSON(t, mat)
	req2, w2 := groupReq(groupBody)
	p.Handle(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("post-login request must succeed, got %d body=%s", w2.Code, w2.Body.String())
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file must be cleared after a successful group resolve, stat err=%v", err)
	}
}

// Empty console_url (cluster node / server-side proxy — no co-installed local
// console) must degrade to URL-less wording, never a broken half-URL, and the
// response must stay a well-formed 401 (main-path robustness).
func TestGroupServe_LoginRequiredNoConsoleURLFallback(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": {CredentialType: "oauth_account", NeedsLogin: true},
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, _ := setupGroupProxy(t, key, route) // console URL deliberately unset

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
		LoginURL string `json:"login_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("401 body must stay valid JSON: %v — %s", err, w.Body.String())
	}
	if resp.LoginURL != "" {
		t.Fatalf("login_url must be empty without console_url, got %q", resp.LoginURL)
	}
	if resp.Error.Type != "authentication_error" {
		t.Fatalf("fallback must keep the displayable type, got %q", resp.Error.Type)
	}
	if strings.Contains(resp.Error.Message, "http://") || strings.Contains(resp.Error.Message, "https://") {
		t.Fatalf("URL-less fallback must not leak a half-assembled URL: %s", resp.Error.Message)
	}
	// Even URL-less, the message must still point at the console page path so
	// the member can find it manually.
	if !strings.Contains(resp.Error.Message, "/user/team-oauth") {
		t.Fatalf("fallback message must name the console page: %s", resp.Error.Message)
	}
}

// Transparent proxy (2026-06-29): after AccountPersona removal, an oauth_group
// pool request forwards the REAL client identity (session/OS) upstream UNCHANGED
// — no per-account synthetic device/session. Guards against re-introducing the
// forgery this code path used to apply (see oauth_inject.go NOTE for the WHY).
func TestGroupServe_PoolPassesRealIdentity(t *testing.T) {
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
	// Upstream (outbound) must carry the REAL client identity, NOT a synthetic
	// per-account one — the whole point of dropping the disguise.
	if tr.session != "REAL-SESSION" {
		t.Fatalf("upstream session must pass through real value unchanged, got %q", tr.session)
	}
	if tr.stainlessOS != "Windows" {
		t.Fatalf("upstream OS must pass through real value unchanged, got %q", tr.stainlessOS)
	}
}

// N8c: a pool account whose upstream returns 401 is cooled down, and a later
// request routes around it (here the only candidate → GROUP_ALL_UNUSABLE 429).
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
	// ALL_UNUSABLE = a genuine rate-limit (recovers when the window resets) → 429,
	// not 503: honest code, and it's the client's call whether to back off + retry.
	if w2.Code != http.StatusTooManyRequests || !strings.Contains(w2.Body.String(), "GROUP_ALL_UNUSABLE") {
		t.Fatalf("cooled-down sole account must yield GROUP_ALL_UNUSABLE 429, got %d: %s", w2.Code, w2.Body.String())
	}
}

// A sole Team OAuth account under a temporary provider throttle must tell the
// client when it can retry, then re-enter routing automatically at the deadline.
// This is the all-accounts-cooling path seen by Claude as GROUP_ALL_UNUSABLE.
func TestGroupServe_TemporaryCooldownAdvertisesRetryAndAutoRecovers(t *testing.T) {
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
	now := time.Unix(1_750_000_000, 0)
	p.poolCooldown.now = func() time.Time { return now }
	p.poolCooldown.markWithState("acc-1", now.Add(2*time.Second), PoolAccountRouteState{
		Status: poolRouteRateLimited, RetryAt: now.Add(2 * time.Second).Unix(),
	})

	req, blocked := groupReq(groupBody)
	p.Handle(blocked, req)
	if blocked.Code != http.StatusTooManyRequests || !strings.Contains(blocked.Body.String(), "GROUP_ALL_UNUSABLE") {
		t.Fatalf("temporarily cooled sole account must yield GROUP_ALL_UNUSABLE 429, got %d: %s", blocked.Code, blocked.Body.String())
	}
	if got := blocked.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("all-cooldown 429 Retry-After=%q, want earliest recovery in 2 seconds", got)
	}
	if tr.calls != 0 {
		t.Fatalf("cooling account must not reach upstream, calls=%d", tr.calls)
	}

	now = now.Add(3 * time.Second)
	req, recovered := groupReq(groupBody)
	p.Handle(recovered, req)
	if recovered.Code != http.StatusOK {
		t.Fatalf("account must re-enter automatically after cooldown, got %d: %s", recovered.Code, recovered.Body.String())
	}
	if tr.calls != 1 {
		t.Fatalf("recovered request must reach upstream once, calls=%d", tr.calls)
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

// §5.5 hard cap: a seat the engine marked Blocked (every pool account at the
// ≤3-人/号 cap) gets 429 — the proxy must NOT fall back to its cap-blind local pick.
func TestGroupServe_BlockedSeatReturns429(t *testing.T) {
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

	// Engine left seat-1 unbound (pool full) → proxy must 429, never route to acc-1.
	cache := NewRoutingOverrideCache()
	cache.StoreAll(1, nil, map[string]bool{routeKey("seat-1", "grp-1"): true})
	p.SetRoutingOverrides(cache)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked seat must 429, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "GROUP_POOL_FULL") {
		t.Fatalf("429 body must carry GROUP_POOL_FULL code: %s", w.Body.String())
	}
	// Neutral wording — the 429 must NOT guess the cause (2026-07-17: the old
	// "add accounts" phrasing misdirected admins on a transient unbind).
	if strings.Contains(w.Body.String(), "per-account user limit") {
		t.Fatalf("blocked 429 must use neutral wording, not the add-accounts phrasing: %s", w.Body.String())
	}
	if tr.host != "" {
		t.Fatalf("blocked request must NOT reach upstream, dialed %q", tr.host)
	}
}

// Deleted access must win over keep-last-known group_runtime. This is the
// authorization fence for a running proxy that still has usable account
// material after Control physically removes the group.
func TestGroupServe_RemovedSeatReturns403WithoutUpstream(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-old", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-old": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-old",
		}, "tok-old"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-old", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-deleted",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	cache := NewRoutingOverrideCache()
	cache.StoreRoutes(2, []routingwire.RouteEntry{{SeatID: route.SeatID, GroupID: route.OauthGroupID, Removed: true}})
	p.SetRoutingOverrides(cache)

	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), groupErrNoCandidates) {
		t.Fatalf("removed route must 403 GROUP_NO_CANDIDATES, got %d body=%s", w.Code, w.Body.String())
	}
	if tr.calls != 0 {
		t.Fatalf("removed route reached upstream %d times", tr.calls)
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
		{AccountID: "acc-1", ProviderCode: "anthropic", Identity: "a1@pool.test"},
		{AccountID: "acc-2", ProviderCode: "anthropic", Identity: "a2@pool.test"},
	}
	identityOf := map[string]string{"acc-1": "a1@pool.test", "acc-2": "a2@pool.test"}
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
	// WAL capture of the REPORTED wire event (ReportableEvent) — the shape the
	// collector → DWD → usage-audit page actually consumes.
	walDir := t.TempDir()
	wal, err := events.NewWALWriter(walDir)
	if err != nil {
		t.Fatalf("NewWALWriter: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	p.SetWAL(wal)
	p.SetReporter(nil, "proxy-grp", "test", "gen-grp", 0, "acc-grp")

	// Probe: learn which account seatassign ranks first (all-200, no cooldowns).
	probeReq, probeW := groupReq(groupBody)
	p.Handle(probeW, probeReq)
	if probeW.Code != http.StatusOK {
		t.Fatalf("probe request failed: %d %s", probeW.Code, probeW.Body.String())
	}
	served1 := tokToAcct[strings.TrimPrefix(tr.auth, "Bearer ")]
	if served1 == "" {
		t.Fatalf("probe outbound auth %q did not map to a known account", tr.auth)
	}

	// The failing request: ONLY the primary 401s. N9 in-request failover must cool
	// it, retry on the other account and return 200 — the client never sees the 401.
	tr.statusByAuth = map[string]int{"Bearer tok-1": 200, "Bearer tok-2": 200}
	primaryTok := "tok-1"
	if served1 == "acc-2" {
		primaryTok = "tok-2"
	}
	tr.statusByAuth["Bearer "+primaryTok] = http.StatusUnauthorized
	req2, w2 := groupReq(groupBody)
	p.Handle(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("in-request failover should succeed via the other account, got %d: %s", w2.Code, w2.Body.String())
	}
	if !p.poolCooldown.skipSet()[served1] {
		t.Fatalf("401 must cool the failing primary %s", served1)
	}
	served2 := tokToAcct[strings.TrimPrefix(tr.auth, "Bearer ")]
	if served2 == "" || served2 == served1 {
		t.Fatalf("failover must serve via a DIFFERENT account; served1=%s served2=%s (auth=%q)", served1, served2, tr.auth)
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
	// Point-in-time audit identity (2026-07-01, usage-audit "selected account"): the
	// REPORTED wire event (ReportableEvent → collector → DWD → usage-audit page) must
	// carry the SERVING account's email as oauth_identity — denormalized at event time
	// so the audit page shows who served even after rename/removal, and it must follow
	// the switch (B's identity, not the cooled A's). 能红: drop the group_serve
	// `rc.OAuthIdentity = res.Identity` stamp → this is "" → fails.
	_ = wal.Close()
	entry := readLastWALEntry(t, walDir)
	if entry.EventJSON.OAuthIdentity != identityOf[served2] {
		t.Fatalf("wire oauth_identity=%q want the SERVING account's identity %q (selected-account audit display)",
			entry.EventJSON.OAuthIdentity, identityOf[served2])
	}
	if entry.EventJSON.AccountID != served2 {
		t.Fatalf("wire account_id=%q want served account %q", entry.EventJSON.AccountID, served2)
	}
}

// TestGroupDegradeMessage locks the per-error-code 503 guidance (finding: all
// group failures collapsed into one "retry shortly" message, misleading a member
// whose access is permanently gone). NO_CANDIDATES must NOT tell the user to
// retry; NO_MATERIAL is the only transient/retryable one; all three differ.
func TestGroupDegradeMessage(t *testing.T) {
	noCand := groupDegradeMessage(groupErrNoCandidates)
	noMat := groupDegradeMessage(groupErrNoMaterial)
	allUnusable := groupDegradeMessage(groupErrAllUnusable)

	// NO_CANDIDATES = permanent until an admin acts → must not say "retry".
	if strings.Contains(strings.ToLower(noCand), "retry") {
		t.Errorf("NO_CANDIDATES message must not tell the user to retry: %q", noCand)
	}
	// NO_MATERIAL = transient → should invite a retry.
	if !strings.Contains(strings.ToLower(noMat), "retry") {
		t.Errorf("NO_MATERIAL message should invite a retry: %q", noMat)
	}
	// All three must be distinct (no collapse to a single generic line).
	if noCand == noMat || noCand == allUnusable || noMat == allUnusable {
		t.Errorf("group degrade messages must differ per code:\n  noCand=%q\n  noMat=%q\n  allUnusable=%q", noCand, noMat, allUnusable)
	}
}

// SyncRail truthful wording (§5.4, 2026-07-03 incident): when the engine's
// assignment rail is STALE/OFFLINE, the pick behind this 401 came from the
// LOCAL ranked fallback and may contradict the engine (the member may already
// be signed into the account the engine actually routed them to). The 401 must
// then say "routing sync unreachable" — not direct the member to sign into a
// possibly-wrong account — and carry the machine-readable reason. A healthy
// rail keeps the normal sign-in prompt with NO reason field (additive contract).
func TestGroupServe_LoginRequiredRailStateWording(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": {CredentialType: "oauth_account", NeedsLogin: true},
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}

	decode := func(w *httptest.ResponseRecorder) (string, string) {
		var resp struct {
			Error struct {
				Message string `json:"message"`
				Reason  string `json:"reason"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("401 body must stay valid JSON: %v — %s", err, w.Body.String())
		}
		return resp.Error.Message, resp.Error.Reason
	}

	// Healthy rail (probe says ok): normal sign-in prompt, no reason field.
	p, _ := setupGroupProxy(t, key, route)
	p.SetConsoleURL("http://127.0.0.1:8090")
	p.SetRoutingRailHealth(func() (string, int64) { return "ok", 0 })
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	msg, reason := decode(w)
	if !strings.Contains(msg, "sign-in") || reason != "" {
		t.Fatalf("healthy rail must keep the sign-in prompt with no reason: msg=%q reason=%q", msg, reason)
	}

	// Degraded rail: truthful wording + machine-readable reason; code and header
	// unchanged (additive-only contract).
	p2, _ := setupGroupProxy(t, key, route)
	p2.SetConsoleURL("http://127.0.0.1:8090")
	p2.SetRoutingRailHealth(func() (string, int64) { return "offline", 23 * 60 })
	req2, w2 := groupReq(groupBody)
	p2.Handle(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("degraded-rail status=%d body=%s", w2.Code, w2.Body.String())
	}
	msg2, reason2 := decode(w2)
	if reason2 != "routing_sync_unavailable" {
		t.Fatalf("degraded rail must set reason=routing_sync_unavailable, got %q", reason2)
	}
	if !strings.Contains(msg2, "unreachable for 23 min") {
		t.Fatalf("degraded wording must state the outage duration: %q", msg2)
	}
	if strings.Contains(msg2, "complete sign-in, then retry") {
		t.Fatalf("degraded wording must NOT blindly direct a sign-in: %q", msg2)
	}
	if got := w2.Header().Get(HeaderAikeyErrorSource); got != groupErrLoginRequired {
		t.Fatalf("header signal must stay %q, got %q", groupErrLoginRequired, got)
	}

	// nil probe (framework off / older wiring): behaves as healthy.
	p3, _ := setupGroupProxy(t, key, route)
	p3.SetConsoleURL("http://127.0.0.1:8090")
	req3, w3 := groupReq(groupBody)
	p3.Handle(w3, req3)
	msg3, reason3 := decode(w3)
	if !strings.Contains(msg3, "sign-in") || reason3 != "" {
		t.Fatalf("nil probe must behave as healthy: msg=%q reason=%q", msg3, reason3)
	}
}
