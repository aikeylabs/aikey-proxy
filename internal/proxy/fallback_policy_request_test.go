package proxy

// fallback_policy_request_test.go — task 1b.6 of openspec change
// `aliyun-aigw-p0-upstream-fallback`: one snapshot per request, shared by the
// whole chain.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/fallbackpolicy"
)

// The snapshot must survive on the context unchanged, and — the part that matters —
// must NOT track the cache afterwards. A request that started under a 120s timeout
// finishes under a 120s timeout even if the rail lands a new policy mid-flight.
func TestRequestSnapshotIsFrozenAtEntry(t *testing.T) {
	c := NewFallbackPolicyCache(nil)
	c.Store(&fallbackpolicy.Policy{UpstreamAttemptTimeoutMs: i64(120_000)}, 1)

	ctx := WithFallbackPolicy(context.Background(), c.SnapshotForRequest())

	// The rail lands a new policy while the request is still in flight.
	c.Store(&fallbackpolicy.Policy{UpstreamAttemptTimeoutMs: i64(5_000)}, 2)

	eff, ok := FallbackPolicyFromContext(ctx)
	if !ok {
		t.Fatal("the entry attached a snapshot but FromContext did not find it")
	}
	if eff.UpstreamAttemptTimeout.Value != 120_000 {
		t.Errorf("in-flight request now sees %d ms, want the 120000 it started with.\n"+
			"A chain that re-reads the cache per hop gives hops 1-2 one timeout and hop 3 "+
			"another. The inputs are identical on the next run and the behavior is not, so "+
			"the timeout looks flaky and nobody suspects the double read",
			eff.UpstreamAttemptTimeout.Value)
	}

	// A request that starts AFTER the change sees the new value — the freeze is
	// per request, not a cache that stopped updating.
	if eff2 := c.SnapshotForRequest(); eff2.UpstreamAttemptTimeout.Value != 5_000 {
		t.Errorf("next request sees %d ms, want 5000 — the snapshot froze the CACHE, not just the request",
			eff2.UpstreamAttemptTimeout.Value)
	}
}

// 🔴 I22 at the last mile: a request that never passed the entry must resolve to
// builtin defaults, never to a zero Effective. Go hands out the zero value for
// free, and "0 ms budget, 0 ms cooldown" is precisely the instant-failure shape
// the three-state rule exists to prevent.
func TestMissingSnapshotResolvesToBuiltinNotZero(t *testing.T) {
	eff, ok := FallbackPolicyFromContext(context.Background())
	if ok {
		t.Error("FromContext claimed a snapshot was attached to a bare context")
	}
	if eff.ChainTotalBudget.Value != fallbackpolicy.DefaultChainTotalBudgetMs ||
		eff.ChainTotalBudget.Source != fallbackpolicy.SourceBuiltin {
		t.Errorf("missing snapshot resolved to %+v, want the builtin default.\n"+
			"A zero here means a 0 ms budget: every request fails instantly, and the console "+
			"shows nothing wrong because the number really is zero", eff.ChainTotalBudget)
	}
	if eff.BindingCooldown.Value == 0 {
		t.Error("missing snapshot produced cooldown=0, which is an EXPLICIT admin choice " +
			"(never cool down), not the absence of one")
	}
}

// A nil cache (a build where the capability is not wired) still serves traffic.
func TestNilCacheSnapshotsBuiltins(t *testing.T) {
	var c *FallbackPolicyCache
	if eff := c.SnapshotForRequest(); eff.IdleGap.Source != fallbackpolicy.SourceBuiltin {
		t.Errorf("nil cache resolved idle gap to %+v, want builtin", eff.IdleGap)
	}
}

// ── 🔴 The fence: exactly one caller ────────────────────────────────────────
//
// Injecting a second `SnapshotForRequest()` — the natural shape of "let me just
// re-read the policy for this hop" — turns this red. That is the whole point:
// 1b.6's rule is one line of prose and would otherwise depend on every future
// author remembering it.
func TestSnapshotForRequestHasExactlyOneCaller(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	var callers []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil || info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		// The definition lives here; tests are allowed to exercise it directly.
		if strings.HasSuffix(path, "fallback_policy_request.go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		for _, line := range strings.Split(string(b), "\n") {
			if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(line, "SnapshotForRequest(") {
				rel, _ := filepath.Rel(root, path)
				callers = append(callers, rel+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(callers) != 1 {
		t.Fatalf("SnapshotForRequest has %d call sites, want exactly 1: %v\n"+
			"More than one means some part of a request resolves the thresholds on its own. "+
			"Fewer than one means the entry stopped attaching the snapshot and every reader "+
			"silently fell back to builtin defaults — which looks like working software.",
			len(callers), callers)
	}
	if !strings.Contains(callers[0], filepath.Join("internal", "supervisor", "supervisor.go")) {
		t.Errorf("the single caller moved to %q. It belongs in the supervisor's data-plane "+
			"handler, which is the one point every request passes through; anywhere deeper "+
			"and some entry (path-prefix routing, the app pipeline) gets no snapshot at all.",
			callers[0])
	}
}
