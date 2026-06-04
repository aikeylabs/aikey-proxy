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
// provider.TokenBreakdown.InputTokens is the TOTAL input (pure + cache_read +
// cache_creation — see provider anthropic totalInput). Charging that whole amount
// at the input rate would over-bill cache tokens by up to ~10x (cache_read is
// 0.1x input). So pricing charges only the PURE input at the input rate and each
// cache portion at its own rate:
//
//	pure_input = inputTotal - cacheRead - cacheCreation   (clamped at 0)
//	cost = pure_input*input + cacheRead*cache_read + cacheCreation*cache_creation
//	       + output*output + reasoning*reasoning
//
// This mirrors exactly how the collector computes billable_amount, so the proxy
// estimate equals the eventual bill for known models (verified 0.000% on real
// data in the D-U8 spike).
func (ps *PriceSummary) Cost(model string, inputTotal, output, cacheRead, cacheCreation, reasoning int) (float64, bool) {
	if ps == nil {
		return 0, false
	}
	mp, ok := ps.Models[model]
	if !ok {
		return 0, false
	}
	pureInput := inputTotal - cacheRead - cacheCreation
	if pureInput < 0 {
		// Defensive: a provider reporting cache > total input shouldn't happen, but
		// never let a negative pure-input credit back usd.
		pureInput = 0
	}
	cost := float64(pureInput)*mp.Input +
		float64(cacheRead)*mp.CacheRead +
		float64(cacheCreation)*mp.CacheCreation +
		float64(output)*mp.Output +
		float64(reasoning)*mp.Reasoning
	return cost, true
}
