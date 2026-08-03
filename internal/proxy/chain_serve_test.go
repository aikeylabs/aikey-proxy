package proxy

// chain_serve_test.go — fences for the upstream-fallback candidate loop
// (openspec change `aliyun-aigw-p0-upstream-fallback`, P2).
//
// Every test drives ONE client request through Handle and asserts what the
// CLIENT saw plus which upstream ADDRESSES were dialed — the two things that
// distinguish a working chain from one that merely compiles.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/fallbackpolicy"
)

// chainCapture records one attempt per upstream host and can fail chosen hosts.
type chainCapture struct {
	mu sync.Mutex
	// hosts in dial order — the chain's observable behavior.
	hosts []string
	// keys in dial order (x-api-key), so a test can prove each hop used ITS OWN
	// credential rather than the primary's.
	keys []string
	// models in dial order, for the per-hop model-mapping fence.
	models []string
	// statusByHost simulates an upstream failure for one address.
	statusByHost map[string]int
	// headerByHost adds response headers (rate-limit evidence, etc).
	headerByHost map[string]http.Header
	// bodyByHost overrides the response body.
	bodyByHost map[string]string
	// delayByHost makes a hop take measurable time, so the whole-chain budget
	// fence can be about elapsed time rather than about scheduling luck.
	delayByHost map[string]time.Duration
}

func (c *chainCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	host := req.URL.Host
	c.hosts = append(c.hosts, host)
	c.keys = append(c.keys, req.Header.Get("x-api-key"))
	model := ""
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		model = extractModelFromJSON(string(b))
	}
	c.models = append(c.models, model)

	if d, ok := c.delayByHost[host]; ok && d > 0 {
		// Honor the request context, exactly as a real RoundTripper does — a fake
		// that ignores cancellation would make every timeout fence pass whether or
		// not the timeout is actually wired.
		select {
		case <-time.After(d):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	st := 200
	if s, ok := c.statusByHost[host]; ok {
		st = s
	}
	h := http.Header{"Content-Type": []string{"application/json"}}
	for k, v := range c.headerByHost[host] {
		h[k] = v
	}
	body := `{"id":"msg_1","model":"claude-sonnet-4-5","content":[]}`
	if b, ok := c.bodyByHost[host]; ok {
		body = b
	}
	return &http.Response{
		StatusCode: st, Header: h,
		Body:    io.NopCloser(strings.NewReader(body)),
		Request: req,
	}, nil
}

func (c *chainCapture) dialed() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.hosts...)
}

// extractModelFromJSON is a crude field read — enough to assert which model name
// left the proxy on each hop without pulling a JSON dependency into the fence.
func extractModelFromJSON(body string) string {
	const marker = `"model":"`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// twoHopChain registers ONE team virtual key whose anthropic protocol has two
// bindings: priority 1 at primary.invalid, priority 2 at fallback.invalid.
func twoHopChain(t *testing.T) (*Proxy, *chainCapture) {
	t.Helper()
	p := setupTestProxy(t, "http://unused.invalid")
	primary := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-chain", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		BaseURL: "https://primary.invalid", PlaintextKey: "key-primary",
		BindingID: "b-primary", CredentialID: "cred-primary",
		Priority: 1, FallbackRole: "primary", RouteGroupID: "rg-1", RouteGroupName: "main",
	}
	fallback := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-chain", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "mock", RouteSource: "team",
		BaseURL: "https://fallback.invalid", PlaintextKey: "key-fallback",
		BindingID: "b-fallback", CredentialID: "cred-fallback",
		Priority: 2, FallbackRole: "fallback", RouteGroupID: "rg-1", RouteGroupName: "main",
	}
	container := *primary
	container.Bindings = []*vkeys.ResolvedRoute{primary, fallback}
	container.BaseURL = ""
	container.PlaintextKey = ""
	container.ProviderCode = ""
	container.ProtocolType = ""
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_chaintest": &container})
	cap := &chainCapture{statusByHost: map[string]int{}, headerByHost: map[string]http.Header{}, bodyByHost: map[string]string{}}
	p.SetTransport(cap)
	return p, cap
}

func chainReq() (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_chaintest")
	return req, httptest.NewRecorder()
}

// ── 2.28: the blocking one. A configured chain must not 409 ────────────────
//
// This is the fence for the defect that made everything else moot: an
// administrator configures a primary and a fallback, and the employee's very
// first request comes back 409 PROVIDER_ROUTE_AMBIGUOUS — on a path where the
// configuration is entirely correct.
func TestChain_ConfiguredChainDoesNotReturn409(t *testing.T) {
	p, cap := twoHopChain(t)
	req, w := chainReq()
	p.Handle(w, req)

	if w.Code == http.StatusConflict {
		t.Fatalf("a correctly configured primary/fallback chain was answered with 409: %s\n"+
			"This is the defect that makes the whole capability unusable — and because the "+
			"word is 'ambiguous', the administrator goes back to re-check configuration "+
			"that was right all along", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := cap.dialed(); len(got) != 1 || got[0] != "primary.invalid" {
		t.Fatalf("dialed %v, want exactly the primary — a healthy chain must not touch the fallback", got)
	}
}

// ── 2.1 / 2.3: the switch itself, and that each hop uses its OWN credential ──
func TestChain_PrimaryFailsOverToFallbackWithItsOwnAddressAndKey(t *testing.T) {
	p, cap := twoHopChain(t)
	cap.statusByHost["primary.invalid"] = 503
	req, w := chainReq()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("client saw %d %s; a chain that switches must present ONE successful response",
			w.Code, w.Body.String())
	}
	got := cap.dialed()
	if len(got) != 2 || got[0] != "primary.invalid" || got[1] != "fallback.invalid" {
		t.Fatalf("dialed %v, want [primary.invalid fallback.invalid] in the administrator's order", got)
	}
	if cap.keys[1] != "key-fallback" {
		t.Errorf("second hop presented %q, want the FALLBACK's own key.\n"+
			"Reusing the primary's credential against the fallback's address is a silent "+
			"authentication failure that looks exactly like the fallback being down",
			cap.keys[1])
	}
	// The switch must be announced, and 🔴 by provider code only — a base_url may
	// be a customer's internal gateway, and echoing it to every key holder
	// broadcasts internal topology.
	hdr := w.Header().Get(observability.HeaderUpstreamFallback)
	if !strings.Contains(hdr, "to=mock") || !strings.Contains(hdr, "attempt=2") {
		t.Errorf("X-Aikey-Fallback=%q, want to=mock and attempt=2", hdr)
	}
	if strings.Contains(hdr, "fallback.invalid") || strings.Contains(hdr, "http") {
		t.Errorf("X-Aikey-Fallback leaked an upstream address: %q", hdr)
	}
}

// ── 2.1 fence: attempts are ADDITIVE, never multiplicative ─────────────────
//
// The rejected design — wrapping the account retry in an upstream-switch
// middleware — makes total attempts (accounts × vendors). A three-account pool
// on a three-vendor chain would be nine sequential upstream round-trips, and the
// tail latency of that is not a regression anyone would attribute to failover.
func TestChain_TotalAttemptsAreAdditiveNotMultiplicative(t *testing.T) {
	p, cap := twoHopChain(t)
	cap.statusByHost["primary.invalid"] = 503
	cap.statusByHost["fallback.invalid"] = 503
	req, w := chainReq()
	p.Handle(w, req)

	if n := len(cap.dialed()); n != 2 {
		t.Fatalf("made %d upstream attempts for a 2-hop chain, want exactly 2 (%v).\n"+
			"More than the chain length means attempts are multiplying somewhere",
			n, cap.dialed())
	}
	if w.Code == http.StatusOK {
		t.Fatal("every hop failed but the client saw 200")
	}
}

// ── 2.7: the two terminal states are different errors ──────────────────────
func TestChain_ExhaustedVersusUnconfigured(t *testing.T) {
	t.Run("all hops failed → EXHAUSTED", func(t *testing.T) {
		p, cap := twoHopChain(t)
		cap.statusByHost["primary.invalid"] = 503
		cap.statusByHost["fallback.invalid"] = 503
		req, w := chainReq()
		p.Handle(w, req)
		if !strings.Contains(w.Body.String(), observability.ErrCodeUpstreamFallbackExhausted) {
			t.Fatalf("body=%s, want %s", w.Body.String(), observability.ErrCodeUpstreamFallbackExhausted)
		}
	})

	t.Run("a one-member group → UNCONFIGURED, and never says retry", func(t *testing.T) {
		p := setupTestProxy(t, "http://unused.invalid")
		only := &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-single", Provider: "anthropic", ProtocolType: "anthropic",
			ProviderCode: "anthropic", RouteSource: "team",
			BaseURL: "https://only.invalid", PlaintextKey: "key-only",
			BindingID: "b-only", Priority: 1, RouteGroupID: "rg-solo", RouteGroupName: "solo",
		}
		p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_chaintest": only})
		cap := &chainCapture{statusByHost: map[string]int{"only.invalid": 503}}
		p.SetTransport(cap)

		req, w := chainReq()
		p.Handle(w, req)

		body := w.Body.String()
		if !strings.Contains(body, observability.ErrCodeUpstreamFallbackUnconfigured) {
			t.Fatalf("body=%s, want %s — 'the chain ran out' and 'there was never a second "+
				"upstream' need OPPOSITE next actions from the administrator",
				body, observability.ErrCodeUpstreamFallbackUnconfigured)
		}
		for _, banned := range []string{"retry", "Retry", "try again"} {
			if strings.Contains(body, banned) {
				t.Errorf("UNCONFIGURED copy contains %q. It is a PERMANENT state: retrying "+
					"cannot succeed until somebody adds a second upstream, so suggesting it "+
					"both wastes the user's time and hides the only action that works", banned)
			}
		}
	})

	t.Run("no group at all → the pre-upgrade single-shot behavior", func(t *testing.T) {
		p := setupTestProxy(t, "http://unused.invalid")
		legacy := &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-legacy", Provider: "anthropic", ProtocolType: "anthropic",
			ProviderCode: "anthropic", RouteSource: "team",
			BaseURL: "https://legacy.invalid", PlaintextKey: "key-legacy",
			BindingID: "b-legacy", Priority: 1,
		}
		p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_chaintest": legacy})
		cap := &chainCapture{
			statusByHost: map[string]int{"legacy.invalid": 503},
			bodyByHost:   map[string]string{"legacy.invalid": `{"error":{"message":"upstream said this"}}`},
		}
		p.SetTransport(cap)

		req, w := chainReq()
		p.Handle(w, req)

		if strings.Contains(w.Body.String(), "UPSTREAM_FALLBACK") {
			t.Fatalf("a row with no route group was given a chain error: %s\n"+
				"No group is Personal's natural resting state and every un-upgraded team "+
				"key's state; it must behave byte-identically to before this change",
				w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "upstream said this") {
			t.Errorf("the upstream's own error stopped reaching the client: %s", w.Body.String())
		}
	})
}

// ── 2.12–2.15: cross-request cooling ───────────────────────────────────────
func TestChain_FailedUpstreamIsSkippedOnTheNextRequest(t *testing.T) {
	p, cap := twoHopChain(t)
	cap.statusByHost["primary.invalid"] = 503

	req, w := chainReq()
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first request: %d %s", w.Code, w.Body.String())
	}

	cap.mu.Lock()
	cap.hosts = nil
	cap.mu.Unlock()

	// 🔴 Clear the STICKY state before the second request. Without this the test
	// passes whether or not cooling works: after a failover the chain is sticky to
	// the hop that served, so the second request would skip the primary for that
	// reason alone. Injecting "never cool" left this test green until the reset was
	// added — a fence that cannot go red is decoration.
	p.chainActivity = newChainActivityStore()

	req, w = chainReq()
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("second request: %d %s", w.Code, w.Body.String())
	}
	got := cap.dialed()
	if len(got) != 1 || got[0] != "fallback.invalid" {
		t.Fatalf("second request dialed %v, want only the fallback.\n"+
			"Without cooling, a forty-minute outage means every single request waits out "+
			"the dead primary first — the user experiences 'why is everything so slow "+
			"today', and the slowness is ours", got)
	}
}

// 🔴 2.14: an evidence-LESS 429 is about the REQUEST, not the upstream.
func TestChain_EvidenceLess429DoesNotCoolTheUpstream(t *testing.T) {
	p, cap := twoHopChain(t)
	cap.statusByHost["primary.invalid"] = 429 // no rate-limit headers at all

	req, w := chainReq()
	p.Handle(w, req)
	_ = w

	if cooling := p.bindingCooldown.cooling("b-primary", time.Now()); cooling {
		t.Fatal("a 429 with no rate-limit evidence cooled the upstream.\n" +
			"That shape is a content-policy or WAF rejection caused by ONE user's prompt; " +
			"punishing the upstream for it pushes the whole organization onto the fallback " +
			"for minutes because of one person's request")
	}
}

// 🔴 2.16: cooling is deliberately NOT persisted, and a restart clears it.
func TestChain_CooldownDoesNotSurviveARestart(t *testing.T) {
	p, cap := twoHopChain(t)
	cap.statusByHost["primary.invalid"] = 503
	req, w := chainReq()
	p.Handle(w, req)
	_ = w
	if cooling := p.bindingCooldown.cooling("b-primary", time.Now()); !cooling {
		t.Fatal("a failed upstream was not cooled at all")
	}

	// A restart is a fresh store, by construction — there is no file to read.
	fresh := newBindingCooldownStore()
	if cooling := fresh.cooling("b-primary", time.Now()); cooling {
		t.Fatal("cooldown survived a restart. A cooldown records a judgement that EXPIRES; " +
			"a restart usually means time has passed, so reading the old judgement back can " +
			"route around an upstream that has already recovered")
	}
}

// 🔴 I14: cooling is a preference, not a ban. With every hop cooling, the chain
// is still walked in the administrator's order rather than refused.
func TestChain_AllCandidatesCoolingStillTriesThemInOrder(t *testing.T) {
	p, cap := twoHopChain(t)
	now := time.Now()
	p.bindingCooldown.until["b-primary"] = now.Add(time.Hour)
	p.bindingCooldown.until["b-fallback"] = now.Add(time.Hour)

	req, w := chainReq()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("every candidate cooling produced %d %s; refusing to serve would be an "+
			"outage we invented ourselves", w.Code, w.Body.String())
	}
	if got := cap.dialed(); len(got) == 0 {
		t.Fatal("no upstream was attempted at all")
	}
}

// ── 2.26 / I15: candidates never cross virtual keys ────────────────────────
//
// A cross-VK borrow breaks two things at once — the call is billed to somebody
// else, and the user reaches a channel they were never granted — and the request
// SUCCEEDS, so nobody reports it. Only a fence finds this.
func TestChain_NeverBorrowsAnotherVirtualKeysUpstream(t *testing.T) {
	p, cap := twoHopChain(t)
	other := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-someone-else", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		BaseURL: "https://someone-else.invalid", PlaintextKey: "key-other",
		BindingID: "b-other", Priority: 1, RouteGroupID: "rg-other",
	}
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_otherkey": other})
	cap.statusByHost["primary.invalid"] = 503
	cap.statusByHost["fallback.invalid"] = 503

	req, w := chainReq()
	p.Handle(w, req)
	_ = w

	for _, host := range cap.dialed() {
		if host == "someone-else.invalid" {
			t.Fatal("the chain borrowed another virtual key's upstream. The request would " +
				"SUCCEED, bill a different team, and grant a channel this key never had — " +
				"there is no symptom for anyone to report")
		}
	}
}

// ── 2.22 / I17: a conversation in progress keeps its upstream ──────────────
func TestChain_StickyWhileAConversationIsInProgress(t *testing.T) {
	p, cap := twoHopChain(t)
	cap.statusByHost["primary.invalid"] = 503

	req, w := chainReq()
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first request: %d", w.Code)
	}
	// The primary is now cooling AND the chain is sticky to the fallback. Clear the
	// cooldown so ONLY stickiness can explain the next hop choice.
	p.bindingCooldown.noteSuccess("b-primary")
	cap.mu.Lock()
	cap.hosts = nil
	cap.mu.Unlock()
	cap.statusByHost["primary.invalid"] = 200

	req, w = chainReq()
	p.Handle(w, req)

	got := cap.dialed()
	if len(got) != 1 || got[0] != "fallback.invalid" {
		t.Fatalf("mid-conversation request dialed %v, want the upstream already serving it.\n"+
			"The same model name can behave subtly differently at different vendors — that "+
			"difference is the entire reason the confidence check exists — so switching "+
			"mid-conversation makes the model's behavior jump under the user", got)
	}
}

// ── 2.21 / I16: no synthetic probe requests, ever ──────────────────────────
//
// The switch-back probe IS the user's next real request. A "hello?" of our own
// would spend real money on every cycle, carry a real credential somewhere nobody
// asked for, and — being far smaller than a real request — could succeed where
// the real one would fail, which is the worst answer because it looks like proof.
func TestChain_NeverSendsASyntheticProbe(t *testing.T) {
	p, cap := twoHopChain(t)
	cap.statusByHost["primary.invalid"] = 503

	req, w := chainReq()
	p.Handle(w, req)
	_ = w

	for i, m := range cap.models {
		if m != "claude-sonnet-4-5" {
			t.Fatalf("attempt %d carried model %q — every upstream call must be the USER's "+
				"request replayed, never one we invented", i, m)
		}
	}
	if n := len(cap.dialed()); n != 2 {
		t.Fatalf("made %d upstream calls for a 2-hop chain; anything extra is a probe", n)
	}
}

// ── 2.31 / 2.32: the whole-chain budget, and its own error code ────────────
func TestChain_BudgetExceededIsItsOwnCode(t *testing.T) {
	p, cap := twoHopChain(t)
	cap.statusByHost["primary.invalid"] = 503
	// The first hop alone outlives the whole-chain budget, so by the time it
	// returns there is no room to start a second. 🔴 The loop must DECLINE to
	// start one, not cut one already in flight: canceling mid-attempt would
	// abort a request that may be about to succeed.
	cap.delayByHost = map[string]time.Duration{"primary.invalid": 30 * time.Millisecond}

	req, w := chainReq()
	req = req.WithContext(WithFallbackPolicy(req.Context(), effectiveWithBudget(10)))
	p.Handle(w, req)

	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("status=%d body=%s, want 504", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, observability.ErrCodeUpstreamFallbackBudgetExceeded) {
		t.Fatalf("body=%s, want %s", body, observability.ErrCodeUpstreamFallbackBudgetExceeded)
	}
	if strings.Contains(body, observability.ErrCodeUpstreamFallbackExhausted) {
		t.Fatal("budget exhaustion was reported as candidate exhaustion. The two point at " +
			"OPPOSITE next actions — raise the number vs go look at the upstreams — so one " +
			"shared code sends half the people who see it in the wrong direction")
	}
}

func TestChain_HonoursTheHopOrderFromPriorityNotInsertionOrder(t *testing.T) {
	p := setupTestProxy(t, "http://unused.invalid")
	// Registered fallback-first on purpose: only priority may decide the order.
	fallback := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-order", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "zzz", RouteSource: "team", BaseURL: "https://second.invalid",
		PlaintextKey: "k2", BindingID: "b2", Priority: 2, RouteGroupID: "rg-o",
	}
	primary := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-order", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "aaa", RouteSource: "team", BaseURL: "https://first.invalid",
		PlaintextKey: "k1", BindingID: "b1", Priority: 1, RouteGroupID: "rg-o",
	}
	container := *primary
	container.Bindings = []*vkeys.ResolvedRoute{fallback, primary}
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_chaintest": &container})
	cap := &chainCapture{statusByHost: map[string]int{}}
	p.SetTransport(cap)

	req, w := chainReq()
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := cap.dialed(); len(got) != 1 || got[0] != "first.invalid" {
		t.Fatalf("dialed %v, want the priority-1 hop first regardless of registration order", got)
	}
}

// effectiveWithBudget builds a policy snapshot with a tiny whole-chain budget and
// otherwise-builtin values.
func effectiveWithBudget(ms int64) fallbackpolicy.Effective {
	eff := fallbackpolicy.Resolve(nil, fallbackpolicy.LocalOverrides{})
	eff.ChainTotalBudget.Value = ms
	eff.ChainTotalBudget.Source = fallbackpolicy.SourceOrg
	return eff
}

// ── 🔴 The upgrade trap: a legacy `aikey use` pin must not kill failover ────
//
// Nearly every developer has run `aikey use` at some point, and those rows carry
// no route group id. Reading the pin-scope table literally — "no group id, so it
// pins that exact binding" — would leave the administrator's chain configured,
// visible in the console, and inert for the entire fleet: the exact
// 「配了但没生效」 failure this change exists to remove, reintroduced by the
// upgrade itself.
func TestChain_LegacyUsePinStillFailsOver(t *testing.T) {
	p, cap := twoHopChain(t)
	p.activeReader = &mockActiveVault{providerBindings: map[string]*vault.ProviderBinding{
		"anthropic": {
			ClientRoute: "anthropic", ProviderCode: "anthropic", ProtocolType: "anthropic",
			KeySourceType: "managed_virtual_key", KeySourceRef: "vk-chain",
			// 🔴 No RouteGroupID — this is what every pre-upgrade pin looks like.
		},
	}}
	cap.statusByHost["primary.invalid"] = 503

	req, w := chainReq()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := cap.dialed(); len(got) != 2 {
		t.Fatalf("dialed %v, want both hops.\n"+
			"A pin written before route groups existed said 'serve this client route from "+
			"THIS KEY', not 'only ever use this one vendor' — that second meaning is "+
			"reserved for an explicit `aikey use --only`, which has to print the "+
			"consequence when the user asks for it", got)
	}
}

// The explicit member pin DOES remove failover — that is the decision (D-1③), and
// the CLI is required to say so at the moment the user pins.
func TestChain_ExplicitMemberPinHasNoFailover(t *testing.T) {
	p, cap := twoHopChain(t)
	p.activeReader = &mockActiveVault{providerBindings: map[string]*vault.ProviderBinding{
		"anthropic": {
			ClientRoute: "anthropic", ProviderCode: "anthropic", ProtocolType: "anthropic",
			KeySourceType: "managed_virtual_key", KeySourceRef: "vk-chain",
			RouteGroupID: "rg-1", // explicit: group + one member = pin one hop
		},
	}}
	cap.statusByHost["primary.invalid"] = 503

	req, w := chainReq()
	p.Handle(w, req)

	if got := cap.dialed(); len(got) != 1 || got[0] != "primary.invalid" {
		t.Fatalf("dialed %v, want only the pinned hop", got)
	}
	if w.Code == http.StatusOK {
		t.Error("the pinned hop failed but the client saw success")
	}
}

// ── The per-attempt timeout: applied only when the ORGANIZATION set one ────
//
// 🔴 The contract's original default (120000, labeled "today's value") was
// disproved during P1b: there is NO per-attempt upstream timeout today.
// `providers.<name>.timeout` is filled in by applyDefaults and read by nothing;
// streaming is unbounded and non-streaming is capped at ten minutes only after
// the client has already disconnected.
//
// So applying the "default" would introduce a 120-second cap that has never
// existed, and a healthy-but-slow long-context generation would be judged an
// upstream failure — then switched away from, then cooled — for the first time,
// on upgrade. That is using a guess to overrule a success.
func TestChain_PerAttemptTimeoutOnlyAppliesWhenTheOrgConfiguredOne(t *testing.T) {
	t.Run("unconfigured: no cap, a slow upstream still succeeds", func(t *testing.T) {
		p, cap := twoHopChain(t)
		cap.delayByHost = map[string]time.Duration{"primary.invalid": 60 * time.Millisecond}

		req, w := chainReq()
		p.Handle(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s — an unconfigured attempt timeout must not cap "+
				"anything; a slow but healthy upstream has to be allowed to finish",
				w.Code, w.Body.String())
		}
		if got := cap.dialed(); len(got) != 1 {
			t.Errorf("dialed %v, want only the primary — nothing should have timed out", got)
		}
	})

	t.Run("configured: the slow hop is cut and the chain moves on", func(t *testing.T) {
		p, cap := twoHopChain(t)
		cap.delayByHost = map[string]time.Duration{"primary.invalid": 200 * time.Millisecond}

		eff := fallbackpolicy.Resolve(nil, fallbackpolicy.LocalOverrides{})
		eff.UpstreamAttemptTimeout.Value = 20
		eff.UpstreamAttemptTimeout.Source = fallbackpolicy.SourceOrg

		req, w := chainReq()
		req = req.WithContext(WithFallbackPolicy(req.Context(), eff))
		start := time.Now()
		p.Handle(w, req)
		elapsed := time.Since(start)

		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want the fallback to have served it",
				w.Code, w.Body.String())
		}
		if got := cap.dialed(); len(got) != 2 {
			t.Fatalf("dialed %v, want both hops — the configured cap must actually cut "+
				"the slow one. A threshold that can be set, stored and displayed but "+
				"never takes effect is the commonest shape of a fake delivery", got)
		}
		if elapsed > 150*time.Millisecond {
			t.Errorf("took %v; the 20ms cap did not bound the first attempt", elapsed)
		}
	})
}

// ── The chain is not capped at three hops ──────────────────────────────────
//
// 🔴 The PRD's vocabulary — "P1 / F1 / F2" — reads like a limit, and the account
// axis really does cap at `groupFailoverMaxSwitches = 3`. Neither applies here:
// that constant governs a different axis with a different cost per attempt (one
// more persona exposed per switch), while a binding chain's length is chosen by
// the administrator out of the providers they have registered.
//
// The only real bound is I29 — one provider per group — so a chain can be as long
// as the organization has distinct providers.
func TestChain_WalksMoreThanThreeHops(t *testing.T) {
	p := setupTestProxy(t, "http://unused.invalid")
	mk := func(code, host string, priority int64) *vkeys.ResolvedRoute {
		return &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-long", Provider: "anthropic", ProtocolType: "anthropic",
			ProviderCode: code, RouteSource: "team",
			BaseURL: "https://" + host, PlaintextKey: "key-" + code, BindingID: "b-" + code,
			Priority: priority, RouteGroupID: "rg-long", RouteGroupName: "long",
		}
	}
	hops := []*vkeys.ResolvedRoute{
		mk("anthropic", "hop1.invalid", 1),
		mk("zhipu", "hop2.invalid", 2),
		mk("gateway-hk", "hop3.invalid", 3),
		mk("gateway-sg", "hop4.invalid", 4),
		mk("gateway-jp", "hop5.invalid", 5),
	}
	container := *hops[0]
	container.Bindings = hops
	container.BaseURL = ""
	container.PlaintextKey = ""
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_chaintest": &container})

	cap := &chainCapture{statusByHost: map[string]int{
		// Everything fails except the LAST hop, so passing requires walking all five.
		"hop1.invalid": 503, "hop2.invalid": 503, "hop3.invalid": 503, "hop4.invalid": 503,
	}}
	p.SetTransport(cap)

	req, w := chainReq()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s — a five-hop chain whose last hop is healthy must succeed",
			w.Code, w.Body.String())
	}
	got := cap.dialed()
	want := []string{"hop1.invalid", "hop2.invalid", "hop3.invalid", "hop4.invalid", "hop5.invalid"}
	if len(got) != len(want) {
		t.Fatalf("dialed %v, want all five in order.\n"+
			"A cap here would silently stop trying upstreams the administrator "+
			"deliberately configured — and the request would fail with every "+
			"later hop untouched and no indication that they were skipped", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hop %d was %s, want %s (order: %v)", i, got[i], want[i], got)
		}
	}
	// The switch header names the hop that finally served, not the third one.
	if hdr := w.Header().Get(observability.HeaderUpstreamFallback); !strings.Contains(hdr, "attempt=5") {
		t.Errorf("X-Aikey-Fallback=%q, want attempt=5", hdr)
	}
}

// ── 6.3 / task 2.8: a FALLBACK hop whose credential is gone is skipped ──────
//
// 🔴 This lives here as a unit fence because staging CANNOT construct it. Making
// a chain's fallback credential revoked means revoking a credential an active
// binding references, and the control plane refuses exactly that with 409
// BIZ_CRED_HAS_ACTIVE_REFS — the open defect where revoking a virtual key leaves
// its bindings active. One defect blocks both a supported admin operation and
// the live regression test for a different requirement.
//
// 🔴 It is deliberately the SECOND hop. The primary's key is resolved on the
// dispatch path (`route = chain.primary()` in handle_dispatch.go, then the vault
// lookup) BEFORE the chain loop runs, so an unusable PRIMARY returns 503
// SECRET_NOT_CONFIGURED instead of stepping over. Measured while writing this.
// The requirement here is about a revoked FALLBACK, which is what the chain
// loop's resolveChainKey skip actually governs.
//
// Two claims, and the second is the easy one to lose: the hop is skipped WITHOUT
// being dialed. It consumed no upstream round-trip, so a request must never go
// out with no key — the vendor's 401 would then be recorded as an upstream
// failure belonging to that provider.
func TestChain_AFallbackHopWithNoUsableCredentialIsSkipped(t *testing.T) {
	p := setupTestProxy(t, "http://unused.invalid")
	mk := func(code, host, key, alias, bindingID string, prio int64) *vkeys.ResolvedRoute {
		return &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-chain", Provider: "anthropic", ProtocolType: "anthropic",
			ProviderCode: code, RouteSource: "team",
			BaseURL: "https://" + host, PlaintextKey: key, KeyAlias: alias,
			BindingID: bindingID, CredentialID: "cred-" + bindingID,
			Priority: prio, RouteGroupID: "rg-1", RouteGroupName: "main",
		}
	}
	first := mk("anthropic", "primary.invalid", "key-primary", "", "b-primary", 1)
	// The revoked one: no plaintext, and a vault alias that is not there.
	second := mk("mock", "revoked.invalid", "", "gone-from-vault", "b-revoked", 2)
	third := mk("zhipu", "third.invalid", "key-third", "", "b-third", 3)

	container := *first
	container.Bindings = []*vkeys.ResolvedRoute{first, second, third}
	container.BaseURL, container.ProviderCode, container.ProtocolType = "", "", ""
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_chaintest": &container})

	cap := &chainCapture{statusByHost: map[string]int{"primary.invalid": 503},
		headerByHost: map[string]http.Header{}, bodyByHost: map[string]string{}}
	p.SetTransport(cap)

	req, w := chainReq()
	p.Handle(w, req)

	dialed := cap.dialed()
	for _, host := range dialed {
		if strings.Contains(host, "revoked.invalid") {
			t.Errorf("the revoked hop was DIALED (%v). A credential that cannot be resolved "+
				"must never reach the network: the request would go out with no key, and the "+
				"vendor's 401 would be recorded as an upstream failure belonging to that provider",
				dialed)
		}
	}
	if len(dialed) != 2 {
		t.Fatalf("dialed %v, want exactly 2 (primary, then third) — the revoked hop must be "+
			"stepped over without consuming a round-trip", dialed)
	}
	if !strings.Contains(dialed[len(dialed)-1], "third.invalid") {
		t.Errorf("the chain ended on %q, want the hop AFTER the revoked one — a skip must "+
			"continue the chain, not end it", dialed[len(dialed)-1])
	}
	if w.Code != http.StatusOK {
		t.Errorf("client got %d, want 200: a chain with a usable hop after the revoked one "+
			"still has an answer", w.Code)
	}
}
