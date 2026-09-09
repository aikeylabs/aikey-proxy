package quota

// unenforceable_test.go — a quota rule that cannot be enforced must be NAMED,
// never silently dropped.
//
// # The defect this closes, and the one it does NOT
//
// 2026-09-04. The MCP rate-limit ruling (task 6.1 / A-3) claimed the quota layer
// reads `limit = 0` as "unlimited" and was therefore lying to operators today.
// Measured, that claim was **wrong**: all three writers refuse a non-positive
// limit — the console form, the control API's `validateSubject`, and the
// directory projection which writes `rules='[]'` and never a rule. Zero is not
// reachable through any supported path, so nobody is being misled.
//
// What IS real is narrower and worth fixing: enforcement drops such a rule
// SILENTLY (`bucketsForSeat`: `LimitAmount <= 0 → continue`), and the delivery
// snapshot serves `subject.Rules` verbatim from the database without
// re-validating them. So a hand-edited row, a future importer, or a regression
// in that validation would reach every proxy and be ignored with no signal — and
// a silently-ignored limit is indistinguishable from a working one: no counter,
// no block, no message.
//
// The repo's logging conventions state the rule directly: a code path that falls
// back to a default must say so.

import (
	"testing"
	"time"
)

func subjectWithRules(id string, rules ...Rule) Subject {
	return Subject{SubjectID: id, SubjectKind: KindSeat, Rules: rules}
}

func TestUnenforceableRulesAreNamedNotSwallowed(t *testing.T) {
	t.Run("a non-positive limit is reported", func(t *testing.T) {
		// 能红: make UnenforceableRules return nil, or narrow its comparison to
		// `< 0` so a zero slips past.
		subs := []Subject{
			subjectWithRules("seat-a",
				Rule{Metric: MetricTokens, Period: "daily", LimitAmount: 0},
				Rule{Metric: MetricUSD, Period: "monthly", LimitAmount: -5},
				Rule{Metric: MetricTokens, Period: "monthly", LimitAmount: 1000},
			),
		}
		got := UnenforceableRules(subs)
		if len(got) != 2 {
			t.Fatalf("reported %d unenforceable rules, want 2 (the 0 and the -5).\n"+
				"A rule enforcement drops without a word is indistinguishable from one that "+
				"works: no counter, no block, no message.\ngot: %+v", len(got), got)
		}
		// 🔴 The report must NAME the rule. "something is wrong" is not actionable
		// on a deployment with hundreds of subjects.
		if got[0].SubjectID != "seat-a" || got[0].Metric != MetricTokens || got[0].Period != "daily" {
			t.Errorf("the report does not identify which rule: %+v", got[0])
		}
	})

	t.Run("a healthy snapshot reports nothing", func(t *testing.T) {
		// 🔴 The other half. A warning that fires on normal configuration is a
		// warning nobody reads, and this one is expected to fire NEVER.
		// 能红: make the comparison `<= 1` or drop the guard entirely.
		subs := []Subject{
			subjectWithRules("seat-b", Rule{Metric: MetricTokens, Period: "daily", LimitAmount: 1}),
			subjectWithRules("seat-c"), // no rules at all — the directory-projected shape
		}
		if got := UnenforceableRules(subs); len(got) != 0 {
			t.Fatalf("a healthy snapshot reported %+v; this WARN must fire on no normal "+
				"configuration, or it will be tuned out before it ever matters", got)
		}
	})

	t.Run("what is reported is exactly what enforcement drops", func(t *testing.T) {
		// 🔴 The invariant that makes the report trustworthy: the reporter and
		// `bucketsForSeat` must agree on which rules are dropped. If they drift,
		// the report either names rules that ARE enforced (noise) or stays quiet
		// about rules that are NOT (the original defect, restored).
		//
		// 能红: change either comparison without changing the other.
		s := &Snapshot{}
		s.ReplaceAll([]Subject{
			subjectWithRules("seat-d",
				Rule{Metric: MetricTokens, Period: "daily", LimitAmount: 0},
				Rule{Metric: MetricTokens, Period: "monthly", LimitAmount: 500},
			),
		})
		buckets := s.tokenBucketsForSeat("seat-d", time.Now())
		if len(buckets) != 1 {
			t.Fatalf("enforcement produced %d token buckets, want 1 (only the 500 rule is "+
				"enforceable): %+v", len(buckets), buckets)
		}
		if buckets[0].Limit != 500 {
			t.Errorf("the enforced bucket is %v, want the 500 rule", buckets[0].Limit)
		}
		reported := UnenforceableRules([]Subject{
			subjectWithRules("seat-d",
				Rule{Metric: MetricTokens, Period: "daily", LimitAmount: 0},
				Rule{Metric: MetricTokens, Period: "monthly", LimitAmount: 500},
			),
		})
		if len(reported) != 1 || reported[0].Period != "daily" {
			t.Fatalf("the reporter and the enforcer disagree about which rule is dropped. "+
				"enforced=%+v reported=%+v", buckets, reported)
		}
	})
}
