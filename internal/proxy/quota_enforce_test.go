package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/quota"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func quotaTestProxy(enabled bool, subjects []quota.Subject) (*Proxy, *quota.Counter) {
	snap := quota.NewSnapshot()
	snap.ReplaceAll(subjects)
	counter := quota.NewCounter()
	p := &Proxy{}
	p.SetQuotaEnforcer(quota.NewEnforcer(snap, counter, enabled))
	return p, counter
}

func TestEnforceQuotaTokens_BlocksOverLimitWith429(t *testing.T) {
	subs := []quota.Subject{{SubjectID: "seat-a", SubjectKind: quota.KindSeat,
		Rules: []quota.Rule{{Metric: quota.MetricTokens, Period: quota.PeriodMonthly, LimitAmount: 100}}}}
	p, counter := quotaTestProxy(true, subs)
	pk := quota.PeriodKey(quota.PeriodMonthly, time.Now())
	counter.Add("seat-a", quota.MetricTokens, pk, 100) // at limit

	route := &vkeys.ResolvedRoute{SeatID: "seat-a"}
	w := httptest.NewRecorder()
	blocked := p.enforceQuota(w, route, discardLogger())

	if !blocked {
		t.Fatal("over-limit request must be blocked")
	}
	if w.Code != 429 {
		t.Errorf("want 429, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "QUOTA_EXCEEDED_TOKEN") {
		t.Errorf("body missing sub-code: %s", w.Body.String())
	}
	if got := w.Header().Get("X-Aikey-Quota-Remaining"); got != "0" {
		t.Errorf("X-Aikey-Quota-Remaining: want 0, got %q", got)
	}
	if w.Header().Get("X-Aikey-Quota-Limit") != "100" {
		t.Errorf("X-Aikey-Quota-Limit wrong: %q", w.Header().Get("X-Aikey-Quota-Limit"))
	}
}

func TestEnforceQuotaTokens_AllowsUnderLimitAndWhenDisabled(t *testing.T) {
	subs := []quota.Subject{{SubjectID: "seat-a", SubjectKind: quota.KindSeat,
		Rules: []quota.Rule{{Metric: quota.MetricTokens, Period: quota.PeriodMonthly, LimitAmount: 100}}}}

	// under limit → not blocked, nothing written
	p, _ := quotaTestProxy(true, subs)
	w := httptest.NewRecorder()
	if p.enforceQuota(w, &vkeys.ResolvedRoute{SeatID: "seat-a"}, discardLogger()) {
		t.Error("under-limit must be allowed")
	}
	if w.Code != 200 { // ResponseRecorder defaults to 200 when nothing written
		t.Errorf("nothing should be written, got code %d", w.Code)
	}

	// disabled enforcer → always allow
	pOff, counterOff := quotaTestProxy(false, subs)
	pk := quota.PeriodKey(quota.PeriodMonthly, time.Now())
	counterOff.Add("seat-a", quota.MetricTokens, pk, 9999) // way over, but disabled
	if pOff.enforceQuota(httptest.NewRecorder(), &vkeys.ResolvedRoute{SeatID: "seat-a"}, discardLogger()) {
		t.Error("disabled enforcer must never block")
	}
}

func TestAccrueQuotaTokens_AddsRawTokenSum(t *testing.T) {
	subs := []quota.Subject{{SubjectID: "seat-a", SubjectKind: quota.KindSeat,
		Rules: []quota.Rule{{Metric: quota.MetricTokens, Period: quota.PeriodMonthly, LimitAmount: 1000}}}}
	p, counter := quotaTestProxy(true, subs)

	// The token metric MUST equal the server's DWD sum (input + output +
	// cached_input + cache_creation + reasoning) so the local count matches the
	// baseline = 10+20+3+4+5 = 42. (DWD.input_tokens is the TOTAL input and cache is
	// a subset, so the server metric counts cache twice; the proxy mirrors that
	// exactly for consistency — see accrueQuotaUsage NOTE.)
	p.accrueQuotaUsage(&vkeys.ResolvedRoute{SeatID: "seat-a"}, provider.TokenBreakdown{
		InputTokens: 10, OutputTokens: 20, CacheReadInputTokens: 3,
		CacheCreationInputTokens: 4, ReasoningTokens: 5,
	}, nil)
	pk := quota.PeriodKey(quota.PeriodMonthly, time.Now())
	if got := counter.Get("seat-a", quota.MetricTokens, pk); got != 42 {
		t.Errorf("token metric: want 42 (matches server DWD sum 10+20+3+4+5), got %v", got)
	}

	// nil route + disabled are safe no-ops
	p.accrueQuotaUsage(nil, provider.TokenBreakdown{InputTokens: 99}, nil)
	if got := counter.Get("seat-a", quota.MetricTokens, pk); got != 42 {
		t.Errorf("nil route must not accrue, got %v", got)
	}
}

// TestServeRoute_QuotaGate_EnforcedAndProbeExempt is the regression guard for the
// 2026-06-04 path-prefix quota-bypass bug: enforceQuota was only wired on the
// legacy dispatch path, so path-prefix / active-sentinel / app traffic ran through
// serveRoute (which accrued usage) but was NEVER blocked. The gate now lives at
// serveRoute — the single funnel ALL real routes pass through — so this test calls
// serveRoute directly to guard that (a) an over-limit non-probe request is 429'd
// before reaching upstream, and (b) probes stay exempt. See
// workflow/CI/bugfix/2026-06-04-quota-not-enforced-on-path-prefix.md.
func TestServeRoute_QuotaGate_EnforcedAndProbeExempt(t *testing.T) {
	var upstreamHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)

	// seat-X is over its monthly usd limit (baseline 0.05 >> limit 0.001).
	snap := quota.NewSnapshot()
	snap.ReplaceAll([]quota.Subject{{
		SubjectID: "seat-X", SubjectKind: quota.KindSeat,
		Rules: []quota.Rule{{Metric: quota.MetricUSD, Period: quota.PeriodMonthly, LimitAmount: 0.001}},
	}})
	counter := quota.NewCounter()
	counter.SetBaseline("seat-X", quota.MetricUSD, quota.PeriodKey(quota.PeriodMonthly, time.Now()), 0.05)
	p.SetQuotaEnforcer(quota.NewEnforcer(snap, counter, true))

	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk", Provider: "anthropic", BaseURL: upstream.URL,
		ProtocolType: "anthropic", SeatID: "seat-X",
	}
	body := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`

	// (a) non-probe over-limit → 429 QUOTA_EXCEEDED_USD, upstream NOT reached.
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	w := httptest.NewRecorder()
	p.serveRoute(w, req, route, prov, "sk-real", "aikey_team_x", time.Now(), discardLogger())
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit non-probe: want 429, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "QUOTA_EXCEEDED_USD") {
		t.Errorf("want QUOTA_EXCEEDED_USD body, got %s", w.Body.String())
	}
	if upstreamHits != 0 {
		t.Errorf("over-limit request must NOT reach upstream, hits=%d", upstreamHits)
	}

	// (b) probe over the SAME over-limit seat → exempt (forwarded, not 429).
	preq := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	preq.Header.Set(headerAikeyProbe, "1")
	pw := httptest.NewRecorder()
	p.serveRoute(pw, preq, route, prov, "sk-real", "aikey_probe_x", time.Now(), discardLogger())
	if pw.Code == http.StatusTooManyRequests {
		t.Errorf("probe must be exempt from quota, got 429: %s", pw.Body.String())
	}
	if upstreamHits != 1 {
		t.Errorf("probe must reach upstream, hits=%d", upstreamHits)
	}
}

// TestServeRoute_QuotaGate_UnquotedVKAlwaysAllowed guards the invariant that a
// virtual key with NO quota limit set is NEVER blocked by the serveRoute gate
// (CLAUDE.md 不变量 6 "无规则=放行" + 2026-06-04 user constraint: unquoted VKs must
// not enter strict/blocking mode). The enforcer is loaded + has an over-limit
// seat-X, but routes for a different (rule-less) seat or with no seat must pass.
func TestServeRoute_QuotaGate_UnquotedVKAlwaysAllowed(t *testing.T) {
	var upstreamHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)
	// Enforcer IS enabled with an over-limit seat-X — proving the gate is live,
	// yet rule-less / seat-less routes still pass.
	snap := quota.NewSnapshot()
	snap.ReplaceAll([]quota.Subject{{
		SubjectID: "seat-X", SubjectKind: quota.KindSeat,
		Rules: []quota.Rule{{Metric: quota.MetricUSD, Period: quota.PeriodMonthly, LimitAmount: 0.001}},
	}})
	counter := quota.NewCounter()
	counter.SetBaseline("seat-X", quota.MetricUSD, quota.PeriodKey(quota.PeriodMonthly, time.Now()), 0.05)
	p.SetQuotaEnforcer(quota.NewEnforcer(snap, counter, true))

	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}
	body := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`

	cases := []struct {
		name string
		seat string
	}{
		{"rule-less seat (no quota configured for this VK)", "seat-Y"},
		{"no seat at all (personal / BYOK VK)", ""},
	}
	for i, c := range cases {
		route := &vkeys.ResolvedRoute{
			VirtualKeyID: "vk", Provider: "anthropic", BaseURL: upstream.URL,
			ProtocolType: "anthropic", SeatID: c.seat,
		}
		req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
		w := httptest.NewRecorder()
		p.serveRoute(w, req, route, prov, "sk-real", "aikey_team_x", time.Now(), discardLogger())
		if w.Code == http.StatusTooManyRequests {
			t.Errorf("%s: unquoted VK must NOT be blocked, got 429: %s", c.name, w.Body.String())
		}
		if upstreamHits != i+1 {
			t.Errorf("%s: must reach upstream (forwarded), hits=%d want=%d", c.name, upstreamHits, i+1)
		}
	}
}
