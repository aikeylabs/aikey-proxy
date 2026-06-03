package proxy

import (
	"net/http"
	"strconv"
	"time"

	"log/slog"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/quota"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// quota_enforce.go — Phase 2 Stage 3 request-path glue for the in-memory token
// quota gate. Kept in its own file so the dispatch / forward / stream hot paths
// only carry one-line calls. All logic is fault-isolated: a nil or disabled
// enforcer makes both functions pure no-ops, so a quota problem can never block
// or slow a request — only a confirmed over-limit blocks (design §8 / 不变量 6).

// enforceQuotaTokens runs the pre-route token-quota check. Returns true when the
// request was blocked (a 429 has been written; the caller MUST return). false =
// allow (quota off, no seat quota, or under limit). Pure in-memory — no I/O.
func (p *Proxy) enforceQuotaTokens(w http.ResponseWriter, route *vkeys.ResolvedRoute, logger *slog.Logger) bool {
	if !p.quota.Enabled() || route == nil {
		return false
	}
	now := time.Now()
	_, v := p.quota.Check(route.SeatID, now)
	if v == nil {
		return false
	}

	p.errors.Add(1)
	reset := quota.PeriodResetAt(v.Period, now)
	limitStr := strconv.FormatFloat(v.Limit, 'f', -1, 64)
	usedStr := strconv.FormatFloat(v.Used, 'f', -1, 64)

	w.Header().Set("X-Aikey-Quota-Limit", limitStr)
	w.Header().Set("X-Aikey-Quota-Used", usedStr)
	w.Header().Set("X-Aikey-Quota-Remaining", "0")
	resetMsg := "the next period"
	if !reset.IsZero() {
		w.Header().Set("X-Aikey-Quota-Reset", reset.UTC().Format(time.RFC3339))
		if secs := int(time.Until(reset).Seconds()); secs > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(secs))
		}
		resetMsg = reset.UTC().Format(time.RFC3339)
	}

	logger.Warn("quota exceeded: token limit",
		"event.name", observability.EventProxyRequestQuotaExceeded,
		"error.code", observability.ErrCodeQuotaExceededToken,
		"subject_id", v.SubjectID,
		"period_key", v.PeriodKey,
		"used", v.Used,
		"limit", v.Limit,
	)
	writeJSONError(w, http.StatusTooManyRequests, "quota_error", observability.ErrCodeQuotaExceededToken,
		"Token quota exceeded for this seat (used "+usedStr+" / limit "+limitStr+"). Resets at "+resetMsg+".")
	return true
}

// accrueQuotaTokens adds a completed request's raw token usage to the seat's
// token counters (design §3.4 raw sum). No-op when quota is off / route nil /
// no usage. Called once per request after the upstream usage is known (both the
// non-streaming and streaming completion paths).
func (p *Proxy) accrueQuotaTokens(route *vkeys.ResolvedRoute, b provider.TokenBreakdown) {
	if !p.quota.Enabled() || route == nil {
		return
	}
	delta := float64(b.InputTokens + b.OutputTokens + b.CacheReadInputTokens +
		b.CacheCreationInputTokens + b.ReasoningTokens)
	p.quota.AddForSeat(route.SeatID, delta, time.Now())
}
