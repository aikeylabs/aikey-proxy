package quota

// pricer.go — proxy-side LOCAL usd pricing from the edge price summary (design
// D-U8/P7). The proxy prices each completed request with the server-delivered
// per-model summary so usd "used" = server baseline + locally-priced increment
// (real-time, offline-capable). The server's full price table stays the billing
// authority; this only fills the gap between baselines and is overwritten by the
// server's exact value on reconnect (D-U8 reconnect reconciliation, P8).

// Cost prices ONE completed request from the summary. Returns (usd, priced):
// priced is false when the model has no summary entry — the caller accrues no usd
// and relies on the token quota floor (the server baseline catches the model up
// once it's priced server-side and re-synced).
//
// Token-type split (correctness — the whole point of exact pricing):
// 方案 A (2026-06-04): provider.TokenBreakdown.InputTokens is now the PURE
// (uncached) input — cache lives in its own fields. So pricing charges the pure
// input at the input rate and each cache portion at its own rate (cache_read is
// ~0.1x input), with NO subtraction here:
//
//	cost = inputPure*input + cacheRead*cache_read + cacheCreation*cache_creation
//	       + output*output + reasoning*reasoning
//
// This mirrors exactly how the collector computes billable_amount (ComputeCost
// with inputIncludesCache=false post-方案-A), so the proxy estimate equals the
// eventual bill for known models. Before 方案 A the proxy received the TOTAL input
// and subtracted cache here; that subtraction moved to the source (the adapter
// now reports pure). See
// roadmap20260320/技术实现/update/20260604-token-input-纯输入语义治本-方案A.md.
func (ps *PriceSummary) Cost(model string, inputPure, output, cacheRead, cacheCreation, reasoning int) (float64, bool) {
	if ps == nil {
		return 0, false
	}
	mp, ok := ps.Models[model]
	if !ok {
		return 0, false
	}
	cost := float64(inputPure)*mp.Input +
		float64(cacheRead)*mp.CacheRead +
		float64(cacheCreation)*mp.CacheCreation +
		float64(output)*mp.Output +
		float64(reasoning)*mp.Reasoning
	return cost, true
}
