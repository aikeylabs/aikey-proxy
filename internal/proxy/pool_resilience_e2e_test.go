package proxy

// pool_resilience_e2e_test.go — narrative end-to-end suite for the 2026-07-19
// pool-availability work, driven through the REAL Handle() entry point and the
// REAL httputil.ReverseProxy (Director → capture writer → ModifyResponse /
// ErrorHandler → cooldown store → multi-attempt failover loop). The only thing
// stubbed is the upstream itself (a programmable RoundTripper) — every piece of
// AiKey logic under test runs for real.
//
// Unlike the per-feature fences (group_failover_test / oauth_pool_cooldown_test
// / oauth_pool_model_tier_test), this suite proves the features COMPOSE: N9
// failover + B1 429 discrimination + P0-B 529/5xx/transport cooling + P1-C
// model-tier scoping all acting on ONE pool across a sequence of requests, with
// client-visible outcome AND internal cooldown state asserted at every step.
//
// Each phase is an independent sub-test with a fresh pool (no cross-phase
// cooldown bleed — TestMain sandboxes AIKEY_RUN_DIR per constructed proxy).

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// upstreamReply scripts one upstream response (or a transport-level failure).
type upstreamReply struct {
	status  int
	headers map[string]string
	body    string // "" → a minimal valid anthropic message body
	connErr error  // non-nil → RoundTrip returns this (no HTTP response = transport failure)
	sse     bool   // true → stream the body as an SSE 200 (first-byte-gate exercise)
}

// upstreamCall records one outbound attempt as the fake upstream saw it.
type upstreamCall struct {
	account string // resolved from the Bearer token
	model   string
	path    string
}

// programmableUpstream is a scriptable fake upstream RoundTripper. The test sets
// reply(call) per phase; every attempt is recorded for count/order assertions.
type programmableUpstream struct {
	mu      sync.Mutex
	tokAcct map[string]string // Bearer token → account id
	reply   func(upstreamCall) upstreamReply
	calls   []upstreamCall
}

func (u *programmableUpstream) RoundTrip(req *http.Request) (*http.Response, error) {
	acct := u.tokAcct[strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")]
	model := ""
	if req.Body != nil {
		if b, err := io.ReadAll(req.Body); err == nil {
			model = extractModelLazy(b)
		}
	}
	call := upstreamCall{account: acct, model: model, path: req.URL.Path}
	u.mu.Lock()
	u.calls = append(u.calls, call)
	fn := u.reply
	u.mu.Unlock()

	rep := upstreamReply{status: 200}
	if fn != nil {
		rep = fn(call)
	}
	if rep.connErr != nil {
		return nil, rep.connErr
	}
	h := http.Header{"Content-Type": {"application/json"}}
	for k, v := range rep.headers {
		h.Set(k, v)
	}
	body := rep.body
	if body == "" {
		body = `{"id":"msg","type":"message","content":[{"type":"text","text":"ok"}],"model":"c","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`
	}
	st := rep.status
	if st == 0 {
		st = 200
	}
	if rep.sse {
		h.Set("Content-Type", "text/event-stream")
	}
	return &http.Response{StatusCode: st, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}

func (u *programmableUpstream) reset(fn func(upstreamCall) upstreamReply) {
	u.mu.Lock()
	u.calls = nil
	u.reply = fn
	u.mu.Unlock()
}

func (u *programmableUpstream) callCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.calls)
}

func (u *programmableUpstream) accountsHit() map[string]int {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := map[string]int{}
	for _, c := range u.calls {
		out[c.account]++
	}
	return out
}

// setupE2EPool seeds an n-account anthropic OAuth pool and installs the
// programmable upstream. Returns the proxy and the upstream handle.
func setupE2EPool(t *testing.T, n int) (*Proxy, *programmableUpstream) {
	t.Helper()
	key := grKey()
	capPct := 95
	refs := make([]vkeys.GroupAccountRef, 0, n)
	mat := map[string]vkeys.GroupRuntimeAccount{}
	tokAcct := map[string]string{}
	for i := 1; i <= n; i++ {
		acc := fmt.Sprintf("acc-%d", i)
		tok := fmt.Sprintf("tok-%d", i)
		refs = append(refs, vkeys.GroupAccountRef{AccountID: acc, ProviderCode: "anthropic"})
		mat[acc] = encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-" + strconv.Itoa(i),
			WindowMaxUtilPct: &capPct,
		}, tok)
		tokAcct["Bearer "+tok] = acc // stored with prefix for convenience? no — strip below
		tokAcct[tok] = acc
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, _ := setupGroupProxy(t, key, route)
	up := &programmableUpstream{tokAcct: tokAcct}
	p.SetTransport(up)
	return p, up
}

func modelBody(model string) string {
	return `{"model":"` + model + `","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
}
func streamBody(model string) string {
	return `{"model":"` + model + `","stream":true,"messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
}

// reply builders --------------------------------------------------------------

func waf429() upstreamReply { // business rejection: 429, NO rate-limit evidence
	return upstreamReply{status: 429, body: `{"type":"error","error":{"type":"api_error","message":"Error"}}`}
}
func exhaustion429(resetIn time.Duration) upstreamReply { // real 5h exhaustion
	return upstreamReply{status: 429, headers: map[string]string{
		"Anthropic-Ratelimit-Unified-Status":         "rate_limited",
		"Anthropic-Ratelimit-Unified-5h-Utilization": "1.0",
		"Anthropic-Ratelimit-Unified-5h-Reset":       strconv.FormatInt(time.Now().Add(resetIn).Unix(), 10),
	}}
}
func fable429(resetIn time.Duration) upstreamReply { // tier-only: 7d_oi exhausted
	return upstreamReply{status: 429, headers: map[string]string{
		"Anthropic-Ratelimit-Unified-7d_oi-Status": "rejected",
		"Anthropic-Ratelimit-Unified-7d_oi-Reset":  strconv.FormatInt(time.Now().Add(resetIn).Unix(), 10),
	}}
}

// ── the narrative ────────────────────────────────────────────────────────────

// Phase 1 (B1): a WAF/business 429 is about the REQUEST, not the account — it
// passes straight through, cools nobody, and makes exactly one upstream attempt
// (no pointless persona-burning failover).
func TestE2E_Pool_WAF429PassesThroughUncooled(t *testing.T) {
	p, up := setupE2EPool(t, 2)
	up.reset(func(upstreamCall) upstreamReply { return waf429() })

	req, w := groupReq(modelBody("claude-sonnet-4-5"))
	p.Handle(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("WAF 429 must reach the client verbatim, got %d", w.Code)
	}
	if up.callCount() != 1 {
		t.Fatalf("WAF 429 must not fail over, got %d attempts", up.callCount())
	}
	if len(p.poolCooldown.skipSet()) != 0 {
		t.Fatalf("WAF 429 must cool nobody, got %v", p.poolCooldown.skipSet())
	}
}

// Phase 2 (N9 + B1): a real exhaustion 429 on the first-picked account is hidden
// from the client — the request fails over in-request to a healthy account and
// returns 200, while the exhausted account is cooled until its window reset.
func TestE2E_Pool_RealExhaustionFailsOverAndCools(t *testing.T) {
	p, up := setupE2EPool(t, 2)
	var firstAcct string
	up.reset(func(c upstreamCall) upstreamReply {
		if firstAcct == "" {
			firstAcct = c.account
			return exhaustion429(2 * time.Hour)
		}
		return upstreamReply{status: 200}
	})

	req, w := groupReq(modelBody("claude-sonnet-4-5"))
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("client must see the failover 200, got %d: %s", w.Code, w.Body.String())
	}
	if up.callCount() != 2 {
		t.Fatalf("want 2 attempts (exhausted + healthy), got %d", up.callCount())
	}
	if !p.poolCooldown.skipSet()[firstAcct] {
		t.Fatalf("the exhausted account %s must be cooled", firstAcct)
	}
	state := p.poolCooldown.routeStateSnapshot()[firstAcct]
	if state.Status != poolRouteWindowExhausted {
		t.Fatalf("confirmed 429 must remain window_exhausted for the drawer, got %+v", state)
	}
}

// Phase 3 (P0-B): a 529 overload is shed immediately — one failover to a healthy
// account, and the overloaded one is cooled so the NEXT request doesn't even
// attempt it.
func TestE2E_Pool_529ShedsImmediately(t *testing.T) {
	p, up := setupE2EPool(t, 2)
	var overloaded string
	up.reset(func(c upstreamCall) upstreamReply {
		if overloaded == "" {
			overloaded = c.account
			return upstreamReply{status: 529}
		}
		return upstreamReply{status: 200}
	})
	req, w := groupReq(modelBody("claude-sonnet-4-5"))
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("529 must fail over to a 200, got %d", w.Code)
	}
	if !p.poolCooldown.skipSet()[overloaded] {
		t.Fatalf("529 must cool the overloaded account immediately")
	}
	// next request never attempts the cooled account.
	up.reset(func(upstreamCall) upstreamReply { return upstreamReply{status: 200} })
	req2, w2 := groupReq(modelBody("claude-sonnet-4-5"))
	p.Handle(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("next request must serve on the healthy account, got %d", w2.Code)
	}
	if hits := up.accountsHit(); hits[overloaded] != 0 {
		t.Fatalf("cooled account must not be attempted next request, hits=%v", hits)
	}
}

// Phase 4 (P0-B): a single transient 5xx on the primary fails over BUT does not
// cool it (one blip tolerated); only the consecutive streak cools it. Proves the
// streak survives across separate client requests.
func TestE2E_Pool_5xxStreakThenCool(t *testing.T) {
	p, up := setupE2EPool(t, 2)
	// primary always 503s; secondary always 200. Each request: primary attempt
	// (503, streak++) → failover → secondary 200. After threshold requests the
	// primary is cooled and drops out.
	var primary string
	up.reset(func(c upstreamCall) upstreamReply {
		if primary == "" {
			primary = c.account
		}
		if c.account == primary {
			return upstreamReply{status: 503}
		}
		return upstreamReply{status: 200}
	})

	for i := 0; i < serverErrStreakThreshold; i++ {
		req, w := groupReq(modelBody("claude-sonnet-4-5"))
		p.Handle(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("req %d: failover must hide the 503, got %d", i+1, w.Code)
		}
		if i < serverErrStreakThreshold-1 && p.poolCooldown.skipSet()[primary] {
			t.Fatalf("req %d: below the streak threshold the primary must NOT be cooled", i+1)
		}
	}
	if !p.poolCooldown.skipSet()[primary] {
		t.Fatalf("%d consecutive 5xx must cool the primary", serverErrStreakThreshold)
	}
}

// Phase 5 (P1-C + Phase 2): the Fable weekly window is exhausted POOL-WIDE.
// Fable requests get the switch-model guidance (429 MODEL_TIER_EXHAUSTED) with
// ZERO wasted upstream attempts once cooled — while Sonnet keeps serving on the
// very same accounts. This is the headline user scenario.
func TestE2E_Pool_FableExhaustedSonnetKeepsServing(t *testing.T) {
	p, up := setupE2EPool(t, 2)
	// every account 429s the Fable window (tier-only); everything else 200.
	up.reset(func(c upstreamCall) upstreamReply {
		if tierForModel(c.model) != nil {
			return fable429(72 * time.Hour)
		}
		return upstreamReply{status: 200}
	})

	// Fable request: fails over across both accounts (each 7d_oi-rejected), both
	// get tier-cooled, and the client is guided to switch model — NOT told the
	// pool is down.
	req, w := groupReq(modelBody("claude-fable-5"))
	p.Handle(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("pool-wide fable exhaustion → 429 guidance, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "MODEL_TIER_EXHAUSTED") || !strings.Contains(body, "switch your model") {
		t.Fatalf("guidance must name the code + switch hint, got %s", body)
	}
	// tier cooled, NOT whole-account cooled.
	if len(p.poolCooldown.skipSet()) != 0 {
		t.Fatalf("fable exhaustion must not whole-account cool, got %v", p.poolCooldown.skipSet())
	}

	// Sonnet on the SAME pool: served, and a SECOND Fable request now makes ZERO
	// upstream attempts (both accounts tier-skipped) → instant guidance.
	up.reset(func(c upstreamCall) upstreamReply {
		if tierForModel(c.model) != nil {
			return fable429(72 * time.Hour)
		}
		return upstreamReply{status: 200}
	})
	sreq, sw := groupReq(modelBody("claude-sonnet-4-5"))
	p.Handle(sw, sreq)
	if sw.Code != http.StatusOK {
		t.Fatalf("sonnet must keep serving on the tier-cooled pool, got %d: %s", sw.Code, sw.Body.String())
	}
	if up.accountsHit()["acc-1"]+up.accountsHit()["acc-2"] == 0 {
		t.Fatal("sonnet must have actually reached an upstream account")
	}

	up.reset(func(c upstreamCall) upstreamReply { return fable429(72 * time.Hour) })
	freq, fw := groupReq(modelBody("claude-fable-5"))
	p.Handle(fw, freq)
	if fw.Code != http.StatusTooManyRequests {
		t.Fatalf("second fable request → guidance 429, got %d", fw.Code)
	}
	if up.callCount() != 0 {
		t.Fatalf("tier-cooled pool must make ZERO fable upstream attempts, got %d", up.callCount())
	}
}

// Phase 6 (N9 first-byte gate, streaming): a streaming request whose upstream
// FAILS BEFORE any byte (401) fails over and the client sees a streamed 200;
// contrast — once SSE bytes flow, no failover is possible (asserted implicitly
// by the success path here reaching the client body).
func TestE2E_Pool_StreamingFailsOverBeforeFirstByte(t *testing.T) {
	p, up := setupE2EPool(t, 2)
	var firstAcct string
	up.reset(func(c upstreamCall) upstreamReply {
		if firstAcct == "" {
			firstAcct = c.account
			return upstreamReply{status: http.StatusUnauthorized} // fails before body
		}
		return upstreamReply{status: 200, sse: true, body: "event: message\ndata: {\"ok\":true}\n\n"}
	})
	req, w := groupReq(streamBody("claude-sonnet-4-5"))
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("streaming 401-before-body must fail over to the streamed 200, got %d", w.Code)
	}
	if up.callCount() != 2 {
		t.Fatalf("want 2 attempts (401 + streamed 200), got %d", up.callCount())
	}
	if !strings.Contains(w.Body.String(), "data:") {
		t.Fatalf("client must receive the SSE payload, got %q", w.Body.String())
	}
}

// Phase 7 (composition): the whole pool is down for DIFFERENT reasons at once —
// account A hard-broken (401), account B overloaded (529). A single request
// fails over A→B, both get cooled, and the client receives the last upstream
// error verbatim (no invented shape). The NEXT request finds an all-cooled pool
// and must preserve the non-quota upstream-unavailable cause as 503.
func TestE2E_Pool_MixedFailuresExhaustThenPreservesCause(t *testing.T) {
	p, up := setupE2EPool(t, 2)
	up.reset(func(c upstreamCall) upstreamReply {
		if strings.HasSuffix(c.account, "1") {
			return upstreamReply{status: http.StatusUnauthorized}
		}
		return upstreamReply{status: 529}
	})
	req, w := groupReq(modelBody("claude-sonnet-4-5"))
	p.Handle(w, req)
	// last attempt's status is flushed verbatim (401 or 529 depending on pick order).
	if w.Code != http.StatusUnauthorized && w.Code != 529 {
		t.Fatalf("exhausted mixed-failure pool must flush the last upstream error, got %d", w.Code)
	}
	if len(p.poolCooldown.skipSet()) != 2 {
		t.Fatalf("both failed accounts must be cooled, got %v", p.poolCooldown.skipSet())
	}
	// next request: everything cooled for non-quota failures → 503, zero attempts.
	up.reset(func(upstreamCall) upstreamReply { return upstreamReply{status: 200} })
	req2, w2 := groupReq(modelBody("claude-sonnet-4-5"))
	p.Handle(w2, req2)
	if w2.Code != http.StatusServiceUnavailable || !strings.Contains(w2.Body.String(), observability.ErrCodeGroupUpstreamUnavailable) {
		t.Fatalf("all-cooled non-quota pool must preserve upstream-unavailable as 503, got %d: %s", w2.Code, w2.Body.String())
	}
	if up.callCount() != 0 {
		t.Fatalf("all-cooled pool must make zero upstream attempts, got %d", up.callCount())
	}
}
