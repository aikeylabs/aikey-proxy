package proxy

// N9 in-request failover fences (2026-07-19, sub2api blueprint — group_failover.go).
// Each test drives ONE client request through Handle and asserts what the CLIENT
// saw vs how many upstream attempts were made — the whole point of N9 is that
// account failures stop being client-visible.

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// twoAccountPool builds a 2-account anthropic OAuth pool and returns the proxy,
// transport capture and tok→account map.
func twoAccountPool(t *testing.T) (*Proxy, *outboundCapture, map[string]string) {
	t.Helper()
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

// A transport-level failure (no HTTP response at all) is synthesized into a 502
// by the ReverseProxy and MUST fail over like any 5xx — the gap sub2api ships
// with (their connection errors dead-end as a client-visible 502).
func TestGroupFailover_TransportErrorRetries(t *testing.T) {
	p, tr, tokToAcct := twoAccountPool(t)
	_, ptok := probePrimary(t, p, tr, tokToAcct)

	tr.errByAuth = map[string]error{"Bearer " + ptok: errors.New("dial tcp: connection refused")}
	req, w := groupReq(groupBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("transport failure must fail over to a 200, got %d: %s", w.Code, w.Body.String())
	}
	if tr.calls != 2 {
		t.Fatalf("want 2 upstream attempts, got %d", tr.calls)
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
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("all-unusable pool surfaces the honest 429, got %d", w.Code)
	}
}

// P0-B: transport-level failures (no HTTP response) count toward the same
// streak — a persistently unreachable account stops being attempted.
func TestGroupCooldown_TransportErrorStreakCools(t *testing.T) {
	p, tr := singleAccountPool(t)
	tr.errByAuth = map[string]error{"Bearer tok-1": errors.New("dial tcp: connection refused")}
	for i := 0; i < serverErrStreakThreshold; i++ {
		req, w := groupReq(groupBody)
		p.Handle(w, req)
		_ = w
	}
	if !p.poolCooldown.skipSet()["acc-1"] {
		t.Fatalf("%d consecutive transport failures must cool the account", serverErrStreakThreshold)
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
		{503, localEngineFailure, false},
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
