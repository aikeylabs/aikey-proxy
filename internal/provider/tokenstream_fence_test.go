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
	stop        string
	model       string
	in          int
	out         int
	cacheRead   int
	cacheCreate int
	reasoning   int
}

var streamGoldens = map[string]tbGolden{
	"anthropic_basic":              {in: 10, out: 25, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "end_turn", model: ""},
	"anthropic_cache":              {in: 1, out: 463, cacheRead: 43000, cacheCreate: 200, reasoning: 0, stop: "", model: ""},
	"anthropic_model":              {in: 10, out: 5, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "end_turn", model: "claude-opus-4-7-20251015"},
	"anthropic_max_tokens":         {in: 5, out: 100, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "max_tokens", model: ""},
	"anthropic_partial_start_only": {in: 8, out: 0, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "", model: ""},
	"anthropic_partial_delta_only": {in: 0, out: 1, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "", model: ""},
	"anthropic_empty":              {in: 0, out: 0, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "", model: ""},
	"openai_basic":                 {in: 5, out: 12, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "stop", model: ""},
	"openai_cached":                {in: 70, out: 50, cacheRead: 30, cacheCreate: 0, reasoning: 0, stop: "", model: ""},
	"openai_reasoning":             {in: 100, out: 500, cacheRead: 0, cacheCreate: 0, reasoning: 400, stop: "", model: ""},
	"openai_model":                 {in: 7, out: 3, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "stop", model: "gpt-4o-mini"},
	"openai_no_space":              {in: 9, out: 5, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "", model: ""},
	"openai_tool_calls":            {in: 20, out: 30, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "tool_calls", model: ""},
	"openai_partial_no_usage":      {in: 0, out: 0, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "", model: ""},
	"openai_empty":                 {in: 0, out: 0, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "", model: ""},
	"kimi_basic":                   {in: 11, out: 4, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "stop", model: ""},
	"generic_basic":                {in: 13, out: 6, cacheRead: 0, cacheCreate: 0, reasoning: 0, stop: "stop", model: ""},
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
