package supervisor

// fallback_policy_rail_test.go — the fences for the threshold rail (openspec change
// `aliyun-aigw-p0-upstream-fallback`, tasks 1b.4 / 1b.4b / 1b.9, and the P6.2
// injection 「手写一个不带失联可见性的轮询替换 SyncRail follower」).
//
// # 🔴 Why this file exists
//
// An audit on 2026-07-30 found `fallback_policy_rail.go` shipped, registered, and
// working — with NOTHING in this package watching it. Its contract properties were
// fenced in three OTHER places (pkg/fallbackpolicy for the three-state semantics
// and the no-secrets assertion, internal/proxy for the request snapshot and the
// health block, aikey-control-master for the 304-counts-as-synced rollout), so the
// capability was genuinely covered — but the two properties that belong to the RAIL
// ITSELF had no fence at all:
//
//	1. that it is REGISTERED into the railset, and
//	2. that it is a declarative follower rather than a hand-written loop.
//
// 🔴 Both failures are silent. An unregistered rail does not error — every threshold
// simply resolves to its builtin default forever, `/status` reports
// `source: builtin` truthfully, and the console shows a value the data plane never
// received. The operator's only symptom is "I changed it in the console and nothing
// happened", which is the exact 「能改能存能显示，就是不生效」 shape this whole phase
// exists to prevent.
//
// The task's own words on why the framework is mandatory (1b.4):
//
//	🚫 不许手写循环。2026-07-03 那次事故就是两条手写轮询「启动时判定一次就永远早退」，
//	静默饿死 7 小时零日志。
//
// A hand-written loop that early-exits at startup looks identical to a working one
// in every test that only asserts the final value.

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestFallbackPolicyRailIsRegisteredIntoTheRailSet — task 1b.4.
//
// 能红: delete `s.fallbackPolicyRail()` from the newRailSet(...) call in
// supervisor.go → every threshold silently resolves to builtin forever.
//
// This is a source assertion rather than a runtime one because constructing a
// Supervisor requires a vault, a generation and a master URL; what needs guarding
// is the one-line registration, and reading it directly is both cheaper and
// harder to fool than a fixture that could pass for the wrong reason.
func TestFallbackPolicyRailIsRegisteredIntoTheRailSet(t *testing.T) {
	src := readSupervisorSource(t, "supervisor.go")

	// 🔴 Match to end of LINE, not to the first `)`. The argument list is itself
	// made of calls — `s.groupRuntimeRail()` — so a `[^)]*` capture stops inside the
	// first argument and reports every rail as unregistered. That mistake made this
	// fence fail against correct source on its first run: a fence whose own bug
	// produces a red is worse than no fence, because the next person's fix is to
	// delete it.
	call := regexp.MustCompile(`(?m)^.*newRailSet\((.*)$`).FindStringSubmatch(src)
	if call == nil {
		t.Fatal("no newRailSet(...) call found in supervisor.go — this fence has stopped " +
			"watching anything, which reads as coverage while providing none")
	}
	if !strings.Contains(call[1], "fallbackPolicyRail()") {
		t.Errorf("the fallback-policy rail is NOT registered into the railset.\n"+
			"newRailSet args were: %s\n"+
			"🔴 This failure is silent: nothing errors, every threshold resolves to its "+
			"builtin default forever, and /status reports source:builtin truthfully. The "+
			"operator sees only 「我在控制台改了，什么都没发生」 — the "+
			"「能改能存能显示，就是不生效」 shape this phase exists to prevent.", call[1])
	}
}

// TestFallbackPolicyRailIsDeclarativeNotAHandWrittenLoop — task 1b.4, and the
// P6.2 injection 「手写一个不带失联可见性的轮询替换 SyncRail follower」.
//
// 能红: replace the railSpec with a `for { ... time.Sleep(...) }` goroutine, or add
// a ticker to the rail file → the banned primitives below appear.
//
// 🔴 What the framework provides that a loop does not, and why losing it is
// invisible: the OK → STALE(3) → OFFLINE(20) state machine, the "keep serving the
// last successful value while disconnected" behavior (I9), and a /status entry.
// A hand-written loop still fetches the policy on the happy path — so a test that
// asserts "the threshold arrived" passes either way. What breaks is only the
// FAILURE path's visibility, and that is precisely what nobody notices until an
// outage.
func TestFallbackPolicyRailIsDeclarativeNotAHandWrittenLoop(t *testing.T) {
	src := readSupervisorSource(t, "fallback_policy_rail.go")

	if !strings.Contains(src, "railSpec{") {
		t.Fatal("fallback_policy_rail.go no longer declares a railSpec — if the rail was " +
			"reimplemented as its own loop, it lost the OK→STALE→OFFLINE state machine, " +
			"the disconnected-keeps-last-known behavior, and its /status entry. The 2026-07-03 " +
			"incident was two hand-written polls that decided once at startup and early-exited " +
			"forever: silently starved for 7 hours with zero log lines")
	}

	// Own scheduling primitives. The rail must be DRIVEN by the framework.
	for _, banned := range []string{"time.NewTicker", "time.Tick(", "time.Sleep(", "go func()"} {
		if strings.Contains(src, banned) {
			t.Errorf("fallback_policy_rail.go contains its own scheduling primitive %q.\n"+
				"🚫 不许手写循环 (task 1b.4). The rail must be a declarative follower so the "+
				"framework — not this file — owns re-evaluating the gate every cycle and making "+
				"failure visible.", banned)
		}
	}
}

// TestFallbackPolicyRailSetsTenSecondsAndOnlyItsOwnInterval — tasks 1b.4 / 1b.4b.
//
// The plan is explicit that 10 seconds applies to THIS rail and that the other rails
// keep their own cadence: 「本 rail 独立设置，🚫 不动另外五条」. `railSpec.interval` is
// per-rail precisely so this is expressible without a global change.
//
// 🔴 Why re-timing another rail would be serious rather than untidy: the cadence
// runs on the CUSTOMER's master, not ours. F-10b's whole ordering rule (conditional
// requests first, THEN shorten the period) exists because getting it backwards
// multiplies a customer's master load by six — 「这个负载发生在客户的机器上，不是我们的」.
func TestFallbackPolicyRailSetsTenSecondsAndOnlyItsOwnInterval(t *testing.T) {
	if fallbackPolicyPollInterval != 10*time.Second {
		t.Errorf("fallbackPolicyPollInterval = %v, want 10s (task 1b.4b). 🔴 The 10-second "+
			"convergence bound is a number sales is allowed to say out loud "+
			"(「改完最长 10 秒到每一台机器」); changing it here silently invalidates that "+
			"commitment", fallbackPolicyPollInterval)
	}

	// The sibling rails must not have been re-timed to match.
	for _, sibling := range []string{"group_runtime_policy.go", "routing_override_policy.go"} {
		src := readSupervisorSource(t, sibling)
		if strings.Contains(src, "fallbackPolicyPollInterval") {
			t.Errorf("%s references fallbackPolicyPollInterval — this change re-timed a rail it "+
				"did not set out to change. The cadence runs on the CUSTOMER's master: F-10b's "+
				"ordering rule (conditional requests first, then shorten) exists because getting "+
				"it wrong multiplies their load, not ours", sibling)
		}
	}
}

// TestFallbackPolicyRailHasNoEditionBranch — task 1b.11.
//
// Personal must reach the builtin defaults through the SAME code path the other
// editions use, by having no control URL, not by an `if edition == personal`.
//
// 🔴 An edition branch is how a capability comes to exist on one edition only —
// which edition-awareness classifies as a bug outright, not a trade-off.
func TestFallbackPolicyRailHasNoEditionBranch(t *testing.T) {
	src := readSupervisorSource(t, "fallback_policy_rail.go")

	for _, banned := range []string{"EditionPersonal", "== \"personal\"", "edition ==", "IsPersonal("} {
		if strings.Contains(src, banned) {
			t.Errorf("fallback_policy_rail.go branches on edition (%q). Task 1b.11 requires "+
				"Personal to walk the SAME path to the builtin defaults — it has no control URL, "+
				"so the framework skips the cycle without counting a failure. Expressing that "+
				"structurally is the requirement; branching on edition is what it forbids", banned)
		}
	}
}

// readSupervisorSource reads a file from this package, stripped of comments.
//
// 🔴 Comments must go first: this file and the rail file both DISCUSS the banned
// primitives by name in order to explain why they are banned. A fence that fires on
// its own rationale gets deleted, and then nothing is watching.
func readSupervisorSource(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v — if the file moved, this fence has stopped watching anything", name, err)
	}
	var b strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
