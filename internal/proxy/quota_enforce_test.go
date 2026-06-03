package proxy

import (
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
	blocked := p.enforceQuotaTokens(w, route, discardLogger())

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
	if p.enforceQuotaTokens(w, &vkeys.ResolvedRoute{SeatID: "seat-a"}, discardLogger()) {
		t.Error("under-limit must be allowed")
	}
	if w.Code != 200 { // ResponseRecorder defaults to 200 when nothing written
		t.Errorf("nothing should be written, got code %d", w.Code)
	}

	// disabled enforcer → always allow
	pOff, counterOff := quotaTestProxy(false, subs)
	pk := quota.PeriodKey(quota.PeriodMonthly, time.Now())
	counterOff.Add("seat-a", quota.MetricTokens, pk, 9999) // way over, but disabled
	if pOff.enforceQuotaTokens(httptest.NewRecorder(), &vkeys.ResolvedRoute{SeatID: "seat-a"}, discardLogger()) {
		t.Error("disabled enforcer must never block")
	}
}

func TestAccrueQuotaTokens_AddsRawTokenSum(t *testing.T) {
	subs := []quota.Subject{{SubjectID: "seat-a", SubjectKind: quota.KindSeat,
		Rules: []quota.Rule{{Metric: quota.MetricTokens, Period: quota.PeriodMonthly, LimitAmount: 1000}}}}
	p, counter := quotaTestProxy(true, subs)

	p.accrueQuotaTokens(&vkeys.ResolvedRoute{SeatID: "seat-a"}, provider.TokenBreakdown{
		InputTokens: 10, OutputTokens: 20, CacheReadInputTokens: 3,
		CacheCreationInputTokens: 4, ReasoningTokens: 5,
	})
	pk := quota.PeriodKey(quota.PeriodMonthly, time.Now())
	if got := counter.Get("seat-a", quota.MetricTokens, pk); got != 42 {
		t.Errorf("raw token sum: want 42 (10+20+3+4+5), got %v", got)
	}

	// nil route + disabled are safe no-ops
	p.accrueQuotaTokens(nil, provider.TokenBreakdown{InputTokens: 99})
	if got := counter.Get("seat-a", quota.MetricTokens, pk); got != 42 {
		t.Errorf("nil route must not accrue, got %v", got)
	}
}
