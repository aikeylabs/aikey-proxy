package proxy

// N9 in-request failover fences (2026-07-19, sub2api blueprint — group_failover.go).
// Each test drives ONE client request through Handle and asserts what the CLIENT
// saw vs how many upstream attempts were made — the whole point of N9 is that
// account failures stop being client-visible.

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/egresstest"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// twoAccountPool builds a 2-account anthropic OAuth pool and returns the proxy,
// transport capture and tok→account map.
func twoAccountPool(t *testing.T) (*Proxy, *outboundCapture, map[string]string) {
	t.Helper()
	key := grKey()
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-1", CredentialID: "cred-1", ProviderCode: "anthropic"},
		{AccountID: "acc-2", CredentialID: "cred-2", ProviderCode: "anthropic"},
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
	p, tr := setupGroupProxy(t, key, route)
	return p, tr, map[string]string{"tok-1": "acc-1", "tok-2": "acc-2"}
}

// probePrimary learns which account seatassign ranks first (an all-200 request),
// then resets the transport counters so the test under measurement starts clean.
func probePrimary(t *testing.T, p *Proxy, tr *outboundCapture, tokToAcct map[string]string) (acct, tok string) {
	t.Helper()
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("probe failed: %d %s", w.Code, w.Body.String())
	}
	tok = strings.TrimPrefix(tr.auth, "Bearer ")
	acct = tokToAcct[tok]
	if acct == "" {
		t.Fatalf("probe auth %q unmapped", tr.auth)
	}
	tr.calls = 0
	return acct, tok
}

// A failover-eligible 5xx on the primary must be retried on the other account —
// the client sees a 200 and TWO upstream attempts happened. Before N9 a 5xx
// passed straight through to the client (and, worse, was never even cooled).
func TestGroupFailover_5xxRetriesOnNextAccount(t *testing.T) {
	p, tr, tokToAcct := twoAccountPool(t)
	primary, ptok := probePrimary(t, p, tr, tokToAcct)

	tr.statusByAuth = map[string]int{"Bearer " + ptok: http.StatusServiceUnavailable}
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("client must see the failover 200, got %d: %s", w.Code, w.Body.String())
	}
	if tr.calls != 2 {
		t.Fatalf("want 2 upstream attempts (primary 503 + switch), got %d", tr.calls)
	}
	if got := tokToAcct[strings.TrimPrefix(tr.auth, "Bearer ")]; got == primary {
		t.Fatalf("second attempt must use a different account, still %s", got)
	}
}

func TestGroupFailover_HardRevokedMemberFallsBackAndReloginRecoversImmediately(t *testing.T) {
	p, tr, tokToAcct := twoAccountPool(t)
	primary, primaryToken := probePrimary(t, p, tr, tokToAcct)
	revokedBody := `{"error":{"type":"authentication_error","message":"OAuth access token has been revoked."}}`
	tr.statusByAuth = map[string]int{"Bearer " + primaryToken: http.StatusUnauthorized}
	tr.bodyByAuth = map[string]string{"Bearer " + primaryToken: revokedBody}

	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK || tr.calls != 2 {
		t.Fatalf("healthy pool member must hide revoked member failure: status=%d calls=%d body=%s", w.Code, tr.calls, w.Body)
	}
	authStates := p.AuthFailureRouteSnapshot()
	if len(authStates) != 1 || authStates[0].OAuthGroupID != "grp-1" || authStates[0].SeatID != "seat-1" || authStates[0].AccountID != primary {
		t.Fatalf("hard revoke must be an exact non-timed member auth failure, got %+v", authStates)
	}

	// The same token is blocked before upstream on the next request.
	tr.calls = 0
	req, w = groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK || tr.calls != 1 {
		t.Fatalf("warm revoked token retried upstream: status=%d calls=%d body=%s", w.Code, tr.calls, w.Body)
	}

	// Master delivers a new token after re-login. Force the former primary so the
	// test proves fingerprint change clears the tombstone immediately.
	key := grKey()
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-1", ProviderCode: "anthropic"},
		{AccountID: "acc-2", ProviderCode: "anthropic"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-1"}, "tok-1"),
		"acc-2": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-2"}, "tok-2"),
	}
	newToken := "tok-relogin"
	entry := mat[primary]
	mat[primary] = encMat(t, key, entry, newToken)
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team", SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_grouptest": route})
	overrides := NewRoutingOverrideCache()
	overrides.StoreAll(1, map[string]string{routeKey("seat-1", "grp-1"): primary}, nil)
	p.SetRoutingOverrides(overrides)
	tr.statusByAuth = nil
	tr.bodyByAuth = nil
	tr.calls = 0
	req, w = groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK || tr.calls != 1 || tr.auth != "Bearer "+newToken {
		t.Fatalf("re-login did not restore former member immediately: status=%d calls=%d auth=%q body=%s", w.Code, tr.calls, tr.auth, w.Body)
	}
	if len(p.AuthFailureRouteSnapshot()) != 0 {
		t.Fatalf("new token must clear old auth-failure projection")
	}
}

func TestGroupFailover_OnlyHardRevokedMemberReturnsLoginRequiredWithoutRetryingToken(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-revoked", ProviderCode: "anthropic", Identity: "member@example.com"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-revoked": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-revoked",
		}, "tok-revoked"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team", SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	tr.status = http.StatusUnauthorized
	tr.bodyByAuth = map[string]string{"Bearer tok-revoked": `{"error":{"type":"authentication_error","message":"OAuth access token has been revoked."}}`}

	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), groupErrLoginRequired) || tr.calls != 1 {
		t.Fatalf("first hard revoke must become login required: status=%d calls=%d body=%s", w.Code, tr.calls, w.Body)
	}
	tr.calls = 0
	req, w = groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), groupErrLoginRequired) || tr.calls != 0 {
		t.Fatalf("warm revoked token reached upstream again: status=%d calls=%d body=%s", w.Code, tr.calls, w.Body)
	}
}

// Every upstream attempt belongs to one logical client request. The provider,
// usage ledger and proxy logs must therefore receive one stable request id even
// when the pool switches A→B before the first client-visible byte.
func TestGroupFailover_RetryPreservesRequestID(t *testing.T) {
	p, tr, tokToAcct := twoAccountPool(t)
	_, ptok := probePrimary(t, p, tr, tokToAcct)

	tr.statusByAuth = map[string]int{"Bearer " + ptok: http.StatusServiceUnavailable}
	tr.requestIDs = nil
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("client must see the failover 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(tr.requestIDs) != 2 {
		t.Fatalf("want two recorded attempts, got request ids %q", tr.requestIDs)
	}
	if tr.requestIDs[0] == "" || tr.requestIDs[0] != tr.requestIDs[1] {
		t.Fatalf("A→B attempts must preserve one non-empty request id, got %q", tr.requestIDs)
	}
}

// An evidence-429 (real exhaustion: unified status flip) fails over; the client
// sees the other account's 200.
func TestGroupFailover_Evidence429Retries(t *testing.T) {
	p, tr, tokToAcct := twoAccountPool(t)
	primary, ptok := probePrimary(t, p, tr, tokToAcct)

	tr.respHeader = http.Header{"Anthropic-Ratelimit-Unified-Status": {"rate_limited"}}
	tr.statusByAuth = map[string]int{"Bearer " + ptok: http.StatusTooManyRequests}
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("evidence-429 must fail over to a 200, got %d: %s", w.Code, w.Body.String())
	}
	if tr.calls != 2 {
		t.Fatalf("want 2 upstream attempts, got %d", tr.calls)
	}
	if !p.poolCooldown.skipSet()[primary] {
		t.Fatalf("the exhausted primary %s must be cooled", primary)
	}
}

func TestGroupFailover_Fallback429IsVisibleButExcludedFromRisk(t *testing.T) {
	p, tr, tokToAcct := twoAccountPool(t)
	primary, _ := probePrimary(t, p, tr, tokToAcct)
	p.signalReporter = &signalReporter{
		rlCounts: make(map[string]int), rlRisk: make(map[string]int),
		rlPrevious: make(map[string]struct{}),
	}
	tr.respHeader = http.Header{"Anthropic-Ratelimit-Unified-Status": {"rate_limited"}}
	tr.statusByAuth = map[string]int{
		"Bearer tok-1": http.StatusTooManyRequests,
		"Bearer tok-2": http.StatusTooManyRequests,
	}
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusTooManyRequests || tr.calls != 2 {
		t.Fatalf("both accounts should be attempted once: status=%d calls=%d body=%s", w.Code, tr.calls, w.Body)
	}

	byCredential := make(map[string]rateLimitSample)
	for _, sample := range p.signalReporter.snapshotRateLimits() {
		byCredential[sample.CredentialID] = sample
	}
	primaryCredential := "cred-1"
	fallbackCredential := "cred-2"
	if primary == "acc-2" {
		primaryCredential, fallbackCredential = fallbackCredential, primaryCredential
	}
	if sample := byCredential[primaryCredential]; sample.Risk429Count != 1 || sample.FallbackCount != 0 {
		t.Fatalf("primary signal=%+v, want risk429=1 fallback=0", sample)
	}
	if sample := byCredential[fallbackCredential]; sample.Risk429Count != 0 || sample.FallbackCount != 1 {
		t.Fatalf("fallback signal=%+v, want visibility-only fallback=1 risk429=0", sample)
	}
}

// A WAF/business 429 (NO rate-limit evidence) is about the REQUEST, not the
// account: switching cannot help and only burns more personas. Exactly ONE
// upstream attempt; the 429 passes through; nobody is cooled.
func TestGroupFailover_WAF429DoesNotRetry(t *testing.T) {
	p, tr, tokToAcct := twoAccountPool(t)
	_, ptok := probePrimary(t, p, tr, tokToAcct)

	tr.statusByAuth = map[string]int{"Bearer " + ptok: http.StatusTooManyRequests}
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("WAF 429 must pass through, got %d", w.Code)
	}
	if tr.calls != 1 {
		t.Fatalf("WAF 429 must not trigger failover: want 1 upstream attempt, got %d", tr.calls)
	}
	if len(p.poolCooldown.skipSet()) != 0 {
		t.Fatalf("WAF 429 must not cool anyone, got %v", p.poolCooldown.skipSet())
	}
}

// A transport-level failure proves the PATH failed, not the account. Two pool
// accounts on that SAME path must not repeat the identical dial in one logical
// request. The path can recover on the next request; neither account is cooled.
func TestGroupPathHealth_TransportErrorDoesNotRetrySamePath(t *testing.T) {
	p, tr, tokToAcct := twoAccountPool(t)
	_, ptok := probePrimary(t, p, tr, tokToAcct)

	tr.errByAuth = map[string]error{"Bearer " + ptok: errors.New("dial tcp: connection refused")}
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("same-path transport failure must remain a non-quota 503, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), observability.ErrCodeGroupUpstreamUnavailable) {
		t.Fatalf("transport path error must retain its explicit non-quota code: %s", w.Body.String())
	}
	if tr.calls != 1 {
		t.Fatalf("same failed path must be dialed once per logical request, got %d attempts", tr.calls)
	}
	if len(p.poolCooldown.skipSet()) != 0 {
		t.Fatalf("transport failure must not cool accounts, got %v", p.poolCooldown.skipSet())
	}
	if got := p.ProviderPathHealthSnapshot(); len(got) != 1 || got[0].State != pathStateSuspect {
		t.Fatalf("transport failure must enter path suspect state, got %+v", got)
	}
}

// A path failure must not disable useful account failover. When the next account
// has a different egress fingerprint, the same logical request is allowed to
// traverse that distinct real SOCKS5 path and reach the Mock Provider.
func TestGroupPathHealth_DifferentEgressPathStillFailsOver(t *testing.T) {
	noEgressBypass(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg","type":"message","content":[{"type":"text","text":"ok"}],"model":"mock","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	defer target.Close()
	goodExit := egresstest.NewSocks5Server(t, "", "")

	key := grKey()
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-bad-path", ProviderCode: "mock", ProtocolType: "anthropic"},
		{AccountID: "acc-good-path", ProviderCode: "mock", ProtocolType: "anthropic"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-bad-path": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ProviderCode: "mock", ProtocolType: "anthropic",
			BaseURL: target.URL, ExpiresAt: 9_000_000_000, ExternalID: "uuid-bad",
			EgressProxyURL: "socks5://127.0.0.1:1",
		}, "tok-bad"),
		"acc-good-path": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ProviderCode: "mock", ProtocolType: "anthropic",
			BaseURL: target.URL, ExpiresAt: 9_000_000_000, ExternalID: "uuid-good",
			EgressProxyURL: "socks5://" + goodExit.Addr(),
		}, "tok-good"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", ProtocolType: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, _ := setupGroupProxy(t, key, route)
	cache := NewRoutingOverrideCache()
	cache.StoreAll(1, map[string]string{routeKey("seat-1", "grp-1"): "acc-bad-path"}, nil)
	p.SetRoutingOverrides(cache)

	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("different egress path must remain eligible and recover in-request, got %d: %s", w.Code, w.Body.String())
	}
	if n, last := goodExit.Stats(); n != 1 || last != hostPort(t, target.URL) {
		t.Fatalf("healthy distinct egress was not traversed exactly once: connects=%d last=%q", n, last)
	}
	if len(p.poolCooldown.skipSet()) != 0 {
		t.Fatalf("path failure must not cool either account, got %v", p.poolCooldown.skipSet())
	}
	paths := p.ProviderPathHealthSnapshot()
	if len(paths) != 1 || paths[0].EgressFingerprint == "" || paths[0].State != pathStateSuspect {
		t.Fatalf("only the failed egress path should remain suspect, got %+v", paths)
	}
}

// A malformed legacy/corrupt egress spec fails before any dial. That local
// construction error is isolated to the selected account/path: another
// logged-in account with a distinct path must still serve the same request.
func TestGroupFailover_InvalidEgressConstructionIsolatedToAccount(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-invalid-egress", ProviderCode: "mock", ProtocolType: "anthropic"},
		{AccountID: "acc-direct", ProviderCode: "mock", ProtocolType: "anthropic"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-invalid-egress": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ProviderCode: "mock", ProtocolType: "anthropic",
			BaseURL: "http://provider.invalid", ExpiresAt: 9_000_000_000, ExternalID: "uuid-invalid",
			EgressProxyURL: "unsupported-egress://127.0.0.1:1",
		}, "tok-invalid"),
		"acc-direct": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ProviderCode: "mock", ProtocolType: "anthropic",
			BaseURL: "http://provider.invalid", ExpiresAt: 9_000_000_000, ExternalID: "uuid-direct",
		}, "tok-direct"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", ProtocolType: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	cache := NewRoutingOverrideCache()
	cache.StoreAll(1, map[string]string{routeKey("seat-1", "grp-1"): "acc-invalid-egress"}, nil)
	p.SetRoutingOverrides(cache)

	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthy account must isolate invalid egress construction, got %d: %s", w.Code, w.Body.String())
	}
	if tr.calls != 1 || tr.auth != "Bearer tok-direct" {
		t.Fatalf("only healthy fallback may reach provider, calls=%d auth=%q", tr.calls, tr.auth)
	}
	if len(p.poolCooldown.skipSet()) != 0 {
		t.Fatalf("invalid egress construction must not become account quota cooldown: %v", p.poolCooldown.skipSet())
	}
}

// When EVERY candidate fails, the client receives the LAST captured upstream
// error verbatim (transparent — never an invented shape), after trying each
// account exactly once.
func TestGroupFailover_AllCandidatesFailFlushesLastError(t *testing.T) {
	p, tr, _ := twoAccountPool(t)

	tr.status = http.StatusUnauthorized // every account 401s
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("exhausted failover must flush the last upstream error (401), got %d", w.Code)
	}
	if tr.calls != 2 {
		t.Fatalf("2 candidates → exactly 2 attempts, got %d", tr.calls)
	}
	if len(p.poolCooldown.skipSet()) != 2 {
		t.Fatalf("both broken accounts must be cooled, got %v", p.poolCooldown.skipSet())
	}
}

// A local AiKey failure on the correctly routed/logged-in account must not be
// overwritten by LOGIN_REQUIRED from the next failover candidate. Live dev2
// regression shape (2026-07-20): test3 logged in + unsupported Hysteria2 egress
// became a misleading "log in test10" 401.
func TestGroupFailover_LocalEgressEngineErrorDoesNotBypassCurrentRoute(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-logged", ProviderCode: "anthropic", Identity: "test3@gmail.com"},
		{AccountID: "acc-needs-login", ProviderCode: "anthropic", Identity: "test10@gmail.com"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-logged": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-logged",
			Identity: "test3@gmail.com",
			EgressProxyURL: `proxies:
  - name: unsupported-hy2
    type: hysteria2
    server: 203.0.113.10
    port: 443
    password: test-only`,
		}, "tok-logged"),
		"acc-needs-login": {CredentialType: "oauth_account", NeedsLogin: true, Identity: "test10@gmail.com"},
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, _ := setupGroupProxy(t, key, route)
	cache := NewRoutingOverrideCache()
	cache.StoreAll(1, map[string]string{routeKey("seat-1", "grp-1"): "acc-logged"}, nil)
	p.SetRoutingOverrides(cache)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("local egress root cause must remain 503, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(HeaderAikeyErrorSource); got != observability.ErrCodeAccountEgressEngine {
		t.Fatalf("error source=%q want %q", got, observability.ErrCodeAccountEgressEngine)
	}
	body := w.Body.String()
	if !strings.Contains(body, observability.ErrCodeAccountEgressEngine) || !strings.Contains(body, "test3@gmail.com") {
		t.Fatalf("response must name the real code and routed account: %s", body)
	}
	if strings.Contains(body, groupErrLoginRequired) || strings.Contains(body, "test10@gmail.com") {
		t.Fatalf("later candidate login state must not mask the root cause: %s", body)
	}
}

// A retryable upstream error from the engine-assigned account must not be
// rewritten as LOGIN_REQUIRED for a different, request-level failover
// candidate. That candidate is not current on /user/team-oauth, so the prompt
// would be both misleading and unactionable. Preserve the captured root cause.
func TestGroupFailover_UpstreamErrorNotMaskedByFailoverCandidateLogin(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-assigned", ProviderCode: "anthropic", Identity: "assigned@example.com"},
		{AccountID: "acc-needs-login", ProviderCode: "anthropic", Identity: "fallback@example.com"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-assigned": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-assigned",
		}, "tok-assigned"),
		"acc-needs-login": {CredentialType: "oauth_account", NeedsLogin: true, Identity: "fallback@example.com"},
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	cache := NewRoutingOverrideCache()
	cache.StoreAll(1, map[string]string{routeKey("seat-1", "grp-1"): "acc-assigned"}, nil)
	p.SetRoutingOverrides(cache)
	tr.status = http.StatusServiceUnavailable

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("captured assigned-account error must remain 503, got %d: %s", w.Code, w.Body.String())
	}
	if tr.calls != 1 {
		t.Fatalf("needs-login fallback has no usable credential and must not be attempted, calls=%d", tr.calls)
	}
	if strings.Contains(w.Body.String(), groupErrLoginRequired) || strings.Contains(w.Body.String(), "fallback@example.com") {
		t.Fatalf("fallback login state must not mask assigned-account failure: %s", w.Body.String())
	}
}

// A no-response path failure has no captured HTTP response. If the next
// account needs login, preserve the concrete path 503 instead of prompting for
// an unrelated account or dereferencing a nil capture writer.
func TestGroupPathHealth_TransportErrorNotMaskedByFailoverCandidateLogin(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-assigned", ProviderCode: "anthropic", Identity: "assigned@example.com"},
		{AccountID: "acc-needs-login", ProviderCode: "anthropic", Identity: "fallback@example.com"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-assigned": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-assigned",
		}, "tok-assigned"),
		"acc-needs-login": {CredentialType: "oauth_account", NeedsLogin: true, Identity: "fallback@example.com"},
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	cache := NewRoutingOverrideCache()
	cache.StoreAll(1, map[string]string{routeKey("seat-1", "grp-1"): "acc-assigned"}, nil)
	p.SetRoutingOverrides(cache)
	tr.errByAuth = map[string]error{"Bearer tok-assigned": errors.New("dial tcp: connection refused")}

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), observability.ErrCodeGroupUpstreamUnavailable) {
		t.Fatalf("transport root cause must remain explicit 503, got %d: %s", w.Code, w.Body.String())
	}
	if tr.calls != 1 {
		t.Fatalf("needs-login fallback must not cause another dial, calls=%d", tr.calls)
	}
	if strings.Contains(w.Body.String(), groupErrLoginRequired) || strings.Contains(w.Body.String(), "fallback@example.com") {
		t.Fatalf("fallback login state must not mask transport failure: %s", w.Body.String())
	}
}

// A confirmed account-wide cooldown is different from the transient 503 above:
// it changes the durable route. When A proves exhausted and B needs login, the
// same request must return an actionable LOGIN_REQUIRED for B rather than flush
// A's 429. The display picker consumes the same cooldown and therefore also
// converges to B.
func TestGroupFailover_ExhaustedAccountPromotesNeedsLoginSuccessor(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-exhausted", ProviderCode: "anthropic", Identity: "exhausted@example.com"},
		{AccountID: "acc-needs-login", ProviderCode: "anthropic", Identity: "fallback@example.com"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-exhausted": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-exhausted",
		}, "tok-exhausted"),
		"acc-needs-login": {CredentialType: "oauth_account", NeedsLogin: true, Identity: "fallback@example.com"},
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	cache := NewRoutingOverrideCache()
	cache.StoreAll(1, map[string]string{routeKey("seat-1", "grp-1"): "acc-exhausted"}, nil)
	p.SetRoutingOverrides(cache)
	tr.status = http.StatusTooManyRequests
	tr.respHeader = http.Header{"Anthropic-Ratelimit-Unified-Status": {"rate_limited"}}

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("confirmed exhaustion must promote the login target, got %d: %s", w.Code, w.Body.String())
	}
	if tr.calls != 1 {
		t.Fatalf("only the exhausted account has usable material, calls=%d", tr.calls)
	}
	if !p.poolCooldown.skipSet()["acc-exhausted"] {
		t.Fatal("evidence 429 must put the exhausted account in durable cooldown")
	}
	if !strings.Contains(w.Body.String(), groupErrLoginRequired) || !strings.Contains(w.Body.String(), "acc-needs-login") {
		t.Fatalf("response must name the promoted login target: %s", w.Body.String())
	}
}

// The switch budget caps total upstream attempts at groupFailoverMaxSwitches+1
// even with more candidates available: the final permitted attempt streams its
// outcome directly (no capture), so the client sees that attempt's error.
func TestGroupFailover_SwitchBudgetCapsAttempts(t *testing.T) {
	key := grKey()
	refs := make([]vkeys.GroupAccountRef, 0, 6)
	mat := map[string]vkeys.GroupRuntimeAccount{}
	for _, n := range []string{"1", "2", "3", "4", "5", "6"} {
		refs = append(refs, vkeys.GroupAccountRef{AccountID: "acc-" + n, ProviderCode: "anthropic"})
		mat["acc-"+n] = encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-" + n,
		}, "tok-"+n)
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)

	tr.status = http.StatusServiceUnavailable // every account 503s
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("capped failover must surface the final attempt's error, got %d", w.Code)
	}
	if want := groupFailoverMaxSwitches + 1; tr.calls != want {
		t.Fatalf("switch budget must cap attempts at %d, got %d", want, tr.calls)
	}
}

// singleAccountPool builds a 1-account pool — the shape where P0-B's cross-
// request cooling is observable in isolation (no alternate to fail over to, so
// every request makes exactly one upstream attempt until the account cools).
func singleAccountPool(t *testing.T) (*Proxy, *outboundCapture) {
	t.Helper()
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-1"}, "tok-1"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	return p, tr
}

// P0-B: a single 529 cools the account IMMEDIATELY (the upstream explicitly
// asked for load shedding) — the next request doesn't touch it.
func TestGroupCooldown_529CoolsImmediately(t *testing.T) {
	p, tr := singleAccountPool(t)
	tr.status = 529
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != 529 {
		t.Fatalf("single-account 529 flushes through, got %d", w.Code)
	}
	if !p.poolCooldown.skipSet()["acc-1"] {
		t.Fatal("529 must cool the account for the overload window")
	}
	// next request: no upstream attempt at all — routed around before forwarding.
	tr.calls = 0
	req2, w2 := groupReq(groupBody)
	p.Handle(w2, req2)
	if tr.calls != 0 {
		t.Fatalf("cooled account must not be attempted, got %d upstream calls", tr.calls)
	}
}

// P0-B: generic 5xx cools only after serverErrStreakThreshold consecutive
// failures — requests 1..N-1 still attempt (transient blips tolerated), the
// threshold request cools, and the request after that makes zero attempts.
func TestGroupCooldown_5xxStreakCoolsAcrossRequests(t *testing.T) {
	p, tr := singleAccountPool(t)
	tr.status = http.StatusServiceUnavailable
	for i := 0; i < serverErrStreakThreshold; i++ {
		req, w := groupReq(groupBody)
		p.Handle(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("req %d: expected the 503 to flush through, got %d", i+1, w.Code)
		}
	}
	if !p.poolCooldown.skipSet()["acc-1"] {
		t.Fatalf("%d consecutive 5xx must cool the account", serverErrStreakThreshold)
	}
	tr.calls = 0
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if tr.calls != 0 {
		t.Fatalf("cooled account must not be attempted, got %d upstream calls", tr.calls)
	}
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), observability.ErrCodeGroupUpstreamUnavailable) {
		t.Fatalf("5xx-cooled pool must preserve upstream-unavailable as 503, got %d: %s", w.Code, w.Body.String())
	}
}

// Transport failures are path-scoped. The second distinct request is the
// half-open probe; after it fails, later requests back off without poisoning the
// account-level cooldown state.
func TestGroupPathHealth_TransportFailuresNeverCoolAccount(t *testing.T) {
	p, tr := singleAccountPool(t)
	tr.errByAuth = map[string]error{"Bearer tok-1": errors.New("dial tcp: connection refused")}
	for i := 0; i < 3; i++ {
		req, w := groupReq(groupBody)
		p.Handle(w, req)
		_ = w
	}
	if len(p.poolCooldown.skipSet()) != 0 {
		t.Fatalf("transport failures must never cool the account, got %v", p.poolCooldown.skipSet())
	}
	if tr.calls != 2 {
		t.Fatalf("first request + one half-open probe should dial twice; third request backs off, got %d", tr.calls)
	}
	if got := p.ProviderPathHealthSnapshot(); len(got) != 1 || got[0].State != pathStateOpen {
		t.Fatalf("repeated transport failures must open the path, got %+v", got)
	}
}

// An account-specific egress failure already has a precise public error code on
// the request that discovers it. Entering the resilience cooldown must not erase
// that cause and turn the next request into a fake quota/rate-limit 429.
func TestGroupPathHealth_EgressFailureStays503WithoutAccountCooldown(t *testing.T) {
	p, tr := singleAccountPool(t)
	tr.errByAuth = map[string]error{
		"Bearer tok-1": &EgressDialError{err: errors.New("rejected username/password")},
	}
	for i := 0; i < 2; i++ {
		req, w := groupReq(groupBody)
		p.Handle(w, req)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), observability.ErrCodeAccountEgressProxy) {
			t.Fatalf("req %d: egress failure must be precise 503, got %d: %s", i+1, w.Code, w.Body.String())
		}
	}
	if len(p.poolCooldown.skipSet()) != 0 {
		t.Fatalf("egress transport failure must not cool the account, got %v", p.poolCooldown.skipSet())
	}
	before := tr.calls
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if tr.calls != before {
		t.Fatalf("open egress path must back off without dialing, before=%d after=%d", before, tr.calls)
	}
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), observability.ErrCodeAccountEgressProxy) {
		t.Fatalf("blocked egress path must remain precise 503, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("blocked path response must include Retry-After")
	}
}

// A transport/egress cooldown is a bounded circuit breaker, not a permanent
// account tombstone. Once it expires, the same group key must automatically
// re-admit the account and recover on the next successful request without a
// proxy restart or any client-side key/config change.
func TestGroupPathHealth_EgressFailureRecoversAfterAdaptiveBackoff(t *testing.T) {
	p, tr := singleAccountPool(t)
	now := time.Unix(1_800_000_000, 0)
	p.pathHealth.now = func() time.Time { return now }
	tr.errByAuth = map[string]error{
		"Bearer tok-1": &EgressDialError{err: errors.New("rejected username/password")},
	}
	for i := 0; i < 2; i++ {
		req, w := groupReq(groupBody)
		p.Handle(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("req %d: want egress 503, got %d: %s", i+1, w.Code, w.Body.String())
		}
	}

	delete(tr.errByAuth, "Bearer tok-1")
	now = now.Add(time.Second)
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("elapsed path backoff must automatically probe and recover, got %d: %s", w.Code, w.Body.String())
	}
	if got := p.ProviderPathHealthSnapshot(); len(got) != 0 {
		t.Fatalf("successful half-open request must close path state, got %+v", got)
	}
}

// P0-B: a success in between resets the streak — flapping upstream never cools.
func TestGroupCooldown_SuccessResetsStreak(t *testing.T) {
	p, tr := singleAccountPool(t)
	do := func(status int) {
		tr.status = status
		req, w := groupReq(groupBody)
		p.Handle(w, req)
		_ = w
	}
	do(http.StatusServiceUnavailable)
	do(http.StatusServiceUnavailable)
	do(http.StatusOK) // resets
	do(http.StatusServiceUnavailable)
	do(http.StatusServiceUnavailable)
	if len(p.poolCooldown.skipSet()) != 0 {
		t.Fatalf("interleaved success must reset the streak, got cooled %v", p.poolCooldown.skipSet())
	}
}

// Unit: eligibility table for the capture gate.
func TestFailoverEligibleResponse(t *testing.T) {
	evidence := http.Header{"Anthropic-Ratelimit-Unified-Status": {"rate_limited"}}
	localEngineFailure := http.Header{HeaderAikeyErrorSource: {observability.ErrCodeAccountEgressEngine}}
	cases := []struct {
		status int
		h      http.Header
		want   bool
	}{
		{401, nil, true},
		{429, nil, false},     // WAF-suspect: no evidence
		{429, evidence, true}, // real exhaustion
		{500, nil, true},
		{502, nil, true},
		{529, nil, true},
		{503, nil, true},
		{503, localEngineFailure, true},
		{200, nil, false},
		{400, nil, false}, // request-shaped error: switching cannot help
		{403, nil, false}, // may be permission/WAF; conservative no-switch this phase
	}
	for _, c := range cases {
		h := c.h
		if h == nil {
			h = http.Header{}
		}
		if got := failoverEligibleResponse(c.status, h); got != c.want {
			t.Errorf("failoverEligibleResponse(%d) = %v, want %v", c.status, got, c.want)
		}
	}
}
