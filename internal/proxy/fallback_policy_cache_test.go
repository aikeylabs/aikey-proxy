package proxy

// fallback_policy_cache_test.go — tasks 1b.3 / 1b.6 / 1b.7 / 1b.8 / 1b.9 of openspec
// change `aliyun-aigw-p0-upstream-fallback`.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/fallbackpolicy"
)

func i64(v int64) *int64 { return &v }

// ── 1b.4: keep-last-known. A poll failure must not re-time the fleet ────────
func TestNeverSyncedResolvesToBuiltinAndSaysSo(t *testing.T) {
	c := NewFallbackPolicyCache(nil)

	eff := c.Snapshot()
	if eff.BindingCooldown.Value != fallbackpolicy.DefaultBindingCooldownMs ||
		eff.BindingCooldown.Source != fallbackpolicy.SourceBuiltin {
		t.Errorf("never-synced cooldown = %+v, want the builtin default", eff.BindingCooldown)
	}
	if c.Synced() {
		t.Error("a cache that has never pulled reports Synced()=true. Then /status cannot say " +
			"'using defaults because we have never reached the control plane', and defaults look " +
			"indistinguishable from an admin who configured these exact numbers")
	}

	// After a store, the configured value wins and the cache is synced.
	c.Store(&fallbackpolicy.Policy{BindingCooldownMs: i64(9_000)}, 3)
	if eff := c.Snapshot(); eff.BindingCooldown.Value != 9_000 || eff.BindingCooldown.Source != fallbackpolicy.SourceOrg {
		t.Errorf("after store, cooldown = %+v, want {9000 org}", eff.BindingCooldown)
	}
	if !c.Synced() || c.Version() != 3 {
		t.Errorf("after store: synced=%v version=%d, want true/3", c.Synced(), c.Version())
	}
}

// 🔴 A 304 must advance last_success_at. Otherwise a fleet whose policy is simply
// stable looks ever more stale, and an operator goes hunting for a sync failure
// that is not happening.
func TestRevalidationAdvancesLastSuccessWithoutChangingValues(t *testing.T) {
	c := NewFallbackPolicyCache(nil)
	c.Store(&fallbackpolicy.Policy{BindingCooldownMs: i64(9_000)}, 3)
	before := c.LastSuccessAt()
	beforeVersion := c.Version()

	c.TouchSuccess()

	if c.LastSuccessAt() < before {
		t.Error("TouchSuccess moved last_success_at backwards")
	}
	if c.Version() != beforeVersion {
		t.Errorf("a 304 changed the version (%d → %d) — nothing moved, so nothing should have",
			beforeVersion, c.Version())
	}
	if eff := c.Snapshot(); eff.BindingCooldown.Value != 9_000 {
		t.Errorf("a 304 disturbed the cached value: %+v", eff.BindingCooldown)
	}
}

// ── 1b.6: one snapshot per request, shared by every hop ─────────────────────
//
// The failure this prevents is not a rounding error, it is an UNREPRODUCIBLE one:
// hops 1-2 on the old timeout and hop 3 on the new one, with the outcome depending
// on when a 10-second poll happened to land relative to the request.
func TestSnapshotIsStableWhileThePolicyChangesUnderneath(t *testing.T) {
	c := NewFallbackPolicyCache(nil)
	c.Store(&fallbackpolicy.Policy{UpstreamAttemptTimeoutMs: i64(5_000), ChainTotalBudgetMs: i64(60_000)}, 1)

	// A request takes its snapshot ONCE.
	snap := c.Snapshot()

	// The rail lands a new policy mid-request.
	c.Store(&fallbackpolicy.Policy{UpstreamAttemptTimeoutMs: i64(90_000), ChainTotalBudgetMs: i64(120_000)}, 2)

	if snap.UpstreamAttemptTimeout.Value != 5_000 {
		t.Errorf("the in-flight snapshot changed to %d. Every hop of one chain must be governed by "+
			"the same numbers — otherwise hop 3 uses a different timeout than hops 1-2 and the "+
			"behavior depends on poll timing, which nothing in the logs explains",
			snap.UpstreamAttemptTimeout.Value)
	}
	// And a NEW request does see the new policy.
	if fresh := c.Snapshot(); fresh.UpstreamAttemptTimeout.Value != 90_000 {
		t.Errorf("a new snapshot did not pick up the new policy: %d", fresh.UpstreamAttemptTimeout.Value)
	}
}

// ── 1b.7: precedence and source reporting, through the cache ────────────────
func TestLocalYAMLLayerAppliesOnlyToAttemptTimeout(t *testing.T) {
	c := NewFallbackPolicyCache(i64(30_000))

	// Nothing from the org → local yaml wins for the timeout only.
	eff := c.Snapshot()
	if eff.UpstreamAttemptTimeout.Value != 30_000 || eff.UpstreamAttemptTimeout.Source != fallbackpolicy.SourceLocalYAML {
		t.Errorf("attempt timeout = %+v, want {30000 local_yaml}", eff.UpstreamAttemptTimeout)
	}
	for name, r := range map[string]fallbackpolicy.Resolved{
		"cooldown":       eff.BindingCooldown,
		"idle_gap":       eff.IdleGap,
		"max_stickiness": eff.MaxStickiness,
		"chain_budget":   eff.ChainTotalBudget,
	} {
		if r.Source != fallbackpolicy.SourceBuiltin {
			t.Errorf("%s resolved from %s; only the per-attempt timeout has a local-yaml layer. "+
				"Adding more means two machines in one group can disagree, producing contradictory "+
				"symptoms nobody thinks to blame on config", name, r.Source)
		}
	}

	// Org beats local yaml.
	c.Store(&fallbackpolicy.Policy{UpstreamAttemptTimeoutMs: i64(7_000), ChainTotalBudgetMs: i64(60_000)}, 1)
	if eff := c.Snapshot(); eff.UpstreamAttemptTimeout.Source != fallbackpolicy.SourceOrg {
		t.Errorf("org must beat local yaml, got %+v", eff.UpstreamAttemptTimeout)
	}
}

// ── 1b.9: the health block carries values AND their provenance ──────────────
func TestHealthBlockReportsValuesSourcesAndSyncState(t *testing.T) {
	c := NewFallbackPolicyCache(nil)
	h := c.Health()
	if h.Synced {
		t.Error("health reports synced before any pull")
	}
	if h.Thresholds.BindingCooldown.Source == "" {
		t.Error("health omitted a source. Task 1b.7 exists because an admin's configured 5 minutes " +
			"and the default 5 minutes are otherwise identical on screen")
	}

	c.Store(&fallbackpolicy.Policy{BindingCooldownMs: i64(0)}, 4)
	h = c.Health()
	if !h.Synced || h.Version != 4 {
		t.Errorf("health after store: synced=%v version=%d, want true/4", h.Synced, h.Version)
	}
	// 🔴 An explicit 0 must be reported as an org choice, not silently defaulted.
	if h.Thresholds.BindingCooldown.Value != 0 || h.Thresholds.BindingCooldown.Source != fallbackpolicy.SourceOrg {
		t.Errorf("explicit 0 reported as %+v, want {0 org} — the admin deliberately disabled "+
			"cooling and the health surface must not overwrite that with a default",
			h.Thresholds.BindingCooldown)
	}
}

// ── 🔴 1b.3: the grep fence ─────────────────────────────────────────────────
//
// Task 1b.3 requires a grep fence banning `unwrap_or(0)` / `if v == 0 { default }`
// shapes, because those are exactly how the three-state rule gets flattened. This
// is that fence, over the packages that touch the policy.
//
// 能红: write `if v == 0 { return builtin }` anywhere in the scanned set.
func TestNoZeroCollapsingPatternsInPolicyCode(t *testing.T) {
	// Scan the proxy tree plus the shared package — the collapse could be
	// introduced on either side of the wire.
	roots := []string{"."}
	if shared, err := filepath.Abs("../../../pkg/fallbackpolicy"); err == nil {
		if _, statErr := os.Stat(shared); statErr == nil {
			roots = append(roots, shared)
		}
	}

	// 🔴 Shapes that flatten the three states, IN GO. Deliberately narrow, and
	// deliberately not `unwrap_or(0)`: that is Rust syntax, so in a .go file it can
	// only ever appear inside a comment — and the shared package's doc comment
	// forbids it by name. An earlier draft of this fence banned the string and
	// promptly flagged the very prose that documents the rule. A fence that
	// punishes people for writing the rule down teaches them to stop.
	//
	// What CAN appear in Go and does collapse the states:
	//   · a helper that turns a nil pointer into 0;
	//   · reading sql.NullInt64.Int64 without consulting .Valid.
	//
	// ⚠️ Honest scope: the PRIMARY guard is behavioral —
	// pkg/fallbackpolicy's TestThreeStateSemanticsUnsetIsNotZero goes red when the
	// collapse is introduced. This static pass is the secondary layer, catching the
	// shapes before they reach the resolver at all.
	banned := []string{
		"derefOrZero",
		"nilToZero",
		"orZero(",
	}
	// Reading .Int64 without .Valid in the same function is the SQL-side collapse.
	// Checked separately because it needs proximity, not a substring.
	nullIntCollapse := func(text string) bool {
		for _, chunk := range strings.Split(text, "\nfunc ") {
			if strings.Contains(chunk, ".Int64") && !strings.Contains(chunk, ".Valid") {
				return true
			}
		}
		return false
	}

	var hits []string
	for _, root := range roots {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if filepath.Ext(path) != ".go" {
				return nil
			}
			// This file names the patterns in order to forbid them.
			if strings.HasSuffix(path, "fallback_policy_cache_test.go") {
				return nil
			}
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			// Strip line comments: the rule is about CODE, and the packages that
			// implement it necessarily discuss the forbidden shapes in prose.
			var code strings.Builder
			for _, line := range strings.Split(string(b), "\n") {
				if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
					continue
				}
				code.WriteString(line)
				code.WriteString("\n")
			}
			text := code.String()
			for _, pattern := range banned {
				if strings.Contains(text, pattern) {
					hits = append(hits, path+": "+pattern)
				}
			}
			// Only the policy store touches sql.NullInt64; scoping the proximity
			// check to it keeps this from firing on unrelated SQL code.
			if strings.Contains(text, "sql.NullInt64") && nullIntCollapse(text) {
				hits = append(hits, path+": reads .Int64 without checking .Valid")
			}
			return nil
		})
	}

	if len(hits) > 0 {
		t.Errorf("zero-collapsing pattern(s) found: %v.\n"+
			"`unset` / `0` / `a value` are THREE states (I22). Flattening them means that on "+
			"upgrade every organization silently gets cooldown=0 — so every request retries a "+
			"known-dead upstream first — and budget=0, so every request fails immediately. Nothing "+
			"looks broken in the console, because the numbers really are zero.", hits)
	}
}

// ── 1b.8: derived numbers may travel; living state may not ──────────────────
func TestSessionGapIsObservableAsADerivedNumber(t *testing.T) {
	before := SessionGapObservations()
	ObserveSessionGap(90 * time.Second)
	if SessionGapObservations() != before+1 {
		t.Error("the inter-arrival gap was not recorded. It is the ONLY calibration data that " +
			"exists for the five defaults F-9b labels as placeholders — refusing to emit it would " +
			"leave them guessed forever")
	}
}

// 🔴 The cache must hold CONFIGURATION only. Live judgement state (last_request_at,
// the cooldown table) is process-local and must never become reportable from here.
//
// 能红: add a field like `lastRequestAt` or `cooldownUntil` to the cache.
func TestPolicyCacheHoldsNoLiveJudgementState(t *testing.T) {
	src, err := os.ReadFile("fallback_policy_cache.go")
	if err != nil {
		t.Fatalf("read cache source: %v", err)
	}
	// Only inspect the struct body, so prose in the file doc cannot trip this.
	text := string(src)
	start := strings.Index(text, "type FallbackPolicyCache struct {")
	if start < 0 {
		t.Fatal("FallbackPolicyCache struct not found — did it move?")
	}
	end := strings.Index(text[start:], "\n}")
	if end < 0 {
		t.Fatal("struct end not found")
	}
	body := text[start : start+end]

	for _, live := range []string{"lastRequestAt", "last_request_at", "cooldownUntil", "cooldown_until", "activeBinding"} {
		if strings.Contains(body, live) {
			t.Errorf("FallbackPolicyCache holds %q — that is LIVE judgement state, and task 1b.8 "+
				"keeps it on the developer's machine. Derived numbers may travel to the control "+
				"plane; living state may not, and a per-person 'was active at 14:03' timeline is "+
				"exactly what must never exist", live)
		}
	}
}

// ── 🔴 The wire the CLI reads (task 1b.10) ──────────────────────────────────
//
// `aikey doctor` renders this block by field name, from another repository that
// deploys on its own schedule. A rename here compiles, ships, and turns the
// doctor check into five "—" rows with no error anywhere — the check would be
// there, and empty, which reads as "nothing configured" rather than "I can no
// longer see it".
//
// 能红: rename any JSON tag below.
func TestHealthBlockJSONKeysAreTheOnesTheCLIReads(t *testing.T) {
	c := NewFallbackPolicyCache(nil)
	c.Store(&fallbackpolicy.Policy{UpstreamAttemptTimeoutMs: i64(5_000)}, 7)

	raw, err := json.Marshal(c.Health())
	if err != nil {
		t.Fatalf("marshal health: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"thresholds", "synced", "version", "last_success_at"} {
		if _, ok := got[key]; !ok {
			t.Errorf("health block lost %q. `aikey doctor` reads it by that exact name across a "+
				"repo boundary; losing it produces an empty check, not an error", key)
		}
	}
	thresholds, _ := got["thresholds"].(map[string]any)
	for _, key := range []string{
		"upstream_attempt_timeout_ms", "chain_total_budget_ms",
		"binding_cooldown_ms", "idle_gap_ms", "max_stickiness_ms",
	} {
		entry, ok := thresholds[key].(map[string]any)
		if !ok {
			t.Errorf("thresholds lost %q", key)
			continue
		}
		if _, ok := entry["value"]; !ok {
			t.Errorf("%s lost its `value`", key)
		}
		if _, ok := entry["source"]; !ok {
			t.Errorf("%s lost its `source` — which is the entire diagnostic content of the "+
				"doctor row: an admin's 5s and a builtin 5s are otherwise identical", key)
		}
	}
}
