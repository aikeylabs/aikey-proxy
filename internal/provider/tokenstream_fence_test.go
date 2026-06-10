package provider

import "testing"

// FENCE TEST for the gap7 incremental-extraction refactor.
//
// Locks the EXACT current ExtractTokenBreakdown(streaming=true) output for every
// fixture in tokenstream_fixtures_test.go. The upcoming incremental extractor
// (parse-and-discard, no whole-body acc) MUST reproduce these byte-identical
// numbers — that is the safety net the refactor is gated on. Goldens were
// captured from the current implementation (see tokenstream_golden_capture_test.go,
// now removed). DO NOT edit a golden to make a refactor pass — a changed number
// means the refactor changed billing behavior and must be investigated.
//
// Why a full-struct golden (not just in/out): the cache / reasoning / model /
// stop_reason fields all flow to DWD billing + receipts; a refactor that silently
// drops one would be a billing regression invisible to an in/out-only test.

type tbGolden struct {
	in, out, cacheRead, cacheCreate, reasoning int
	stop, model                                string
}

var streamGoldens = map[string]tbGolden{
	"anthropic_basic":             {10, 25, 0, 0, 0, "end_turn", ""},
	"anthropic_cache":             {1, 463, 43000, 200, 0, "", ""},
	"anthropic_model":             {10, 5, 0, 0, 0, "end_turn", "claude-opus-4-7-20251015"},
	"anthropic_max_tokens":        {5, 100, 0, 0, 0, "max_tokens", ""},
	"anthropic_partial_start_only": {8, 0, 0, 0, 0, "", ""},
	"anthropic_partial_delta_only": {0, 1, 0, 0, 0, "", ""},
	"anthropic_empty":             {0, 0, 0, 0, 0, "", ""},
	"openai_basic":                {5, 12, 0, 0, 0, "stop", ""},
	"openai_cached":               {70, 50, 30, 0, 0, "", ""},
	"openai_reasoning":            {100, 500, 0, 0, 400, "", ""},
	"openai_model":                {7, 3, 0, 0, 0, "stop", "gpt-4o-mini"},
	"openai_no_space":             {9, 5, 0, 0, 0, "", ""},
	"openai_tool_calls":           {20, 30, 0, 0, 0, "tool_calls", ""},
	"openai_partial_no_usage":     {0, 0, 0, 0, 0, "", ""},
	"openai_empty":                {0, 0, 0, 0, 0, "", ""},
	"kimi_basic":                  {11, 4, 0, 0, 0, "stop", ""},
	"generic_basic":               {13, 6, 0, 0, 0, "stop", ""},
}

func assertGolden(t *testing.T, name string, br TokenBreakdown, g tbGolden) {
	t.Helper()
	if br.InputTokens != g.in || br.OutputTokens != g.out ||
		br.CacheReadInputTokens != g.cacheRead || br.CacheCreationInputTokens != g.cacheCreate ||
		br.ReasoningTokens != g.reasoning || br.StopReason != g.stop || br.Model != g.model {
		t.Errorf("%s: got In=%d Out=%d CacheRead=%d CacheCreate=%d Reasoning=%d Stop=%q Model=%q\n"+
			"        want In=%d Out=%d CacheRead=%d CacheCreate=%d Reasoning=%d Stop=%q Model=%q",
			name, br.InputTokens, br.OutputTokens, br.CacheReadInputTokens, br.CacheCreationInputTokens,
			br.ReasoningTokens, br.StopReason, br.Model,
			g.in, g.out, g.cacheRead, g.cacheCreate, g.reasoning, g.stop, g.model)
	}
}

// TestTokenStreamFence_WholeBody locks the current whole-body extraction output.
func TestTokenStreamFence_WholeBody(t *testing.T) {
	if len(streamGoldens) != len(streamFenceFixtures) {
		t.Fatalf("golden count %d != fixture count %d — every fixture must have a golden",
			len(streamGoldens), len(streamFenceFixtures))
	}
	for _, f := range streamFenceFixtures {
		g, ok := streamGoldens[f.name]
		if !ok {
			t.Errorf("no golden for fixture %q", f.name)
			continue
		}
		br := f.prov.ExtractTokenBreakdown([]byte(f.sse), true, nil)
		assertGolden(t, f.name, br, g)
	}
}

// TestTokenStreamFence_AccumulatorEqualsWholeBody is the gap7 equivalence gate:
// feeding the incremental StreamAccumulator line-by-line must produce the SAME
// TokenBreakdown as the untouched whole-body ExtractTokenBreakdown (and the
// golden). This binds the new parse-and-discard path to the existing billing
// extractor so they cannot silently diverge.
func TestTokenStreamFence_AccumulatorEqualsWholeBody(t *testing.T) {
	for _, f := range streamFenceFixtures {
		fac, ok := f.prov.(StreamAccumulatorFactory)
		if !ok {
			t.Errorf("%s: provider does not implement StreamAccumulatorFactory", f.name)
			continue
		}
		acc := fac.NewStreamAccumulator()
		// Feed exactly as the whole-body extractor iterates: split on \n, strip
		// the data: prefix, feed each payload.
		for _, raw := range bytesSplitLines(f.sse) {
			feedStreamLine(acc, []byte(raw))
		}
		got := acc.Result()
		assertGolden(t, f.name+"[accumulator]", got, streamGoldens[f.name])

		// Also assert exact equality against the live whole-body call (defends
		// against a future golden edit that drifts both out of sync with code).
		want := f.prov.ExtractTokenBreakdown([]byte(f.sse), true, nil)
		if got != want {
			t.Errorf("%s: accumulator %+v != whole-body %+v", f.name, got, want)
		}
	}
}

func bytesSplitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
