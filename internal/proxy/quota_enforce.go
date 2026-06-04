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

// enforceQuota runs the pre-route quota check (token AND usd). Returns true when
// the request was blocked (a 429 has been written; the caller MUST return).
// false = allow (quota off, no seat quota, or under limit). Pure in-memory — no
// I/O (usd "used" is read from the in-memory usd source, never computed here).
func (p *Proxy) enforceQuota(w http.ResponseWriter, route *vkeys.ResolvedRoute, logger *slog.Logger) bool {
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

	// Metric-specific error code + label (token vs cost). Default to token.
	code, label := observability.ErrCodeQuotaExceededToken, "Token"
	if v.Metric == quota.MetricUSD {
		code, label = observability.ErrCodeQuotaExceededUSD, "Cost ($)"
	}
	// D-U7/P9 budget-mode fail-closed: not an at/over-limit hit but "can't verify"
	// (stale baseline / server unreachable) under a strict deployment.
	if v.FailClosedStale {
		code = observability.ErrCodeQuotaDegradedBlock
	}

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

	logger.Warn("quota exceeded",
		"event.name", observability.EventProxyRequestQuotaExceeded,
		"error.code", code,
		"metric", v.Metric,
		"subject_id", v.SubjectID,
		"period_key", v.PeriodKey,
		"used", v.Used,
		"limit", v.Limit,
	)
	msg := label + " quota exceeded for this seat (used " + usedStr + " / limit " + limitStr + "). Resets at " + resetMsg + "."
	if v.FailClosedStale {
		msg = "Cost ($) quota cannot be verified right now (control server unreachable); blocked by strict budget policy (used " + usedStr + " / limit " + limitStr + "). Retry when connectivity is restored."
	}
	writeJSONError(w, http.StatusTooManyRequests, "quota_error", code, msg)
	return true
}

// accrueQuotaUsage adds a completed request's usage to the seat's quota counters:
// raw tokens (design §3.4) AND locally-priced usd (D-U8/P7, priced from the edge
// summary). No-op when quota is off / route nil / no usage. Called once per
// request after the upstream usage is known (non-streaming + streaming paths).
func (p *Proxy) accrueQuotaUsage(route *vkeys.ResolvedRoute, b provider.TokenBreakdown, logger *slog.Logger) {
	if !p.quota.Enabled() || route == nil {
		return
	}
	now := time.Now()
	// tokens: this sum MUST match the server's DWD token metric so the proxy's local
	// increment lines up with the baseline it tops up. The server metric is
	// `input_tokens + output + cached_input + cache_creation + reasoning`
	// (collector dwdMetricSumExpr), and DWD.input_tokens is the TOTAL input — cache
	// is a SUBSET of it (verified on real data: total_tokens == input + output, and
	// cache_read+cache_creation <= input_tokens). So the metric counts the cache
	// buckets twice (inside input AND added again); the proxy mirrors that EXACTLY
	// here so enforcement stays consistent with the baseline.
	// NOTE(2026-06-04): the metric (and billable) double-counting cache vs the true
	// token/cost is a real but SEPARATE billing-semantics question in the collector
	// (changes customer bills — large blast radius); do NOT "fix" it here in
	// isolation or the proxy would drift below the server baseline. See
	// bugfix/2026-06-04-quota-token-metric-cache-semantics.md.
	delta := float64(b.InputTokens + b.OutputTokens + b.CacheReadInputTokens +
		b.CacheCreationInputTokens + b.ReasoningTokens)
	p.quota.AddForSeat(route.SeatID, delta, now)
	// usd (D-U8/P7): price this request locally from the edge summary (correct
	// token-type split is inside Cost). Unknown model with a summary present →
	// WARN (usd not counted; token floor + server baseline backstop). No summary
	// yet (rollout / Personal) → silent.
	if _, priced, hadSummary := p.quota.AccrueUsdForSeat(route.SeatID, b.Model,
		b.InputTokens, b.OutputTokens, b.CacheReadInputTokens,
		b.CacheCreationInputTokens, b.ReasoningTokens, now); hadSummary && !priced && logger != nil {
		logger.Warn("quota usd: request model not in edge price summary; usd not counted (token floor applies)",
			"event.name", observability.EventProxyQuotaModelUnpriced,
			"model", b.Model,
			"seat_id", route.SeatID,
		)
	}
}
