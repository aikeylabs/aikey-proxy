package proxy

// filter_cache_packswap_test.go — the verdict cache must follow the detector's
// LIVE ruleset, not the detector's BINARY version.
//
// 用户诉求 2026-08-13: "删除之后，proxy 侧需要能够感知并且禁用该词库".
//
// The user path these tests protect (two halves, two repos):
//
//	admin deletes a rule on the console
//	  → control-master bumps the pack's distribution version
//	    (workflow/CI/bugfix/20260813-rule-crud-does-not-bump-pack-version.md)
//	  → the detector pulls it and hot-swaps its compiled ruleset in place,
//	    WITHOUT restarting — so apphook.Status().Version, which is written once
//	    from the child's ready handshake, is byte-identical before and after
//	  → the proxy must stop replaying the mask verdict it memoized under the old
//	    ruleset.  ← THIS FILE
//
// packSwapHook reproduces exactly that: a mutable active ruleset behind a FIXED
// Status().Version, plus a content version that moves with the ruleset.

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// packSwapHook is a fake compliance filter whose active ruleset can be swapped
// at runtime the way a real detector's can. `banned` is the ruleset; `version`
// is what the hook reports as its effective-content token ("" = it cannot say,
// e.g. the child is unreachable).
type packSwapHook struct {
	banned  map[string]bool
	version string
	calls   int
	mu      sync.Mutex
}

// version stays a parameter even though every current case passes "pack-v1":
// it is the axis this fake exists to model (the doc above spells out that ""
// means "the hook cannot report its content token"), and the swap tests below
// mutate it at runtime. Collapsing it to a constant to satisfy unparam would
// delete the knob a future "detector cannot answer op=ListPacks" case needs.
//
//nolint:unparam // deliberate: see above
func newPackSwapHook(version string, banned ...string) *packSwapHook {
	h := &packSwapHook{banned: map[string]bool{}, version: version}
	for _, b := range banned {
		h.banned[b] = true
	}
	return h
}

func (h *packSwapHook) Name() string { return "pack-swap-fake" }

func (h *packSwapHook) Detect(_ context.Context, req *apphook.Request) *apphook.Response {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	for phrase := range h.banned {
		if strings.Contains(string(req.Payload), phrase) {
			return &apphook.Response{Action: apphook.ActionMask, MutatedPayload: []byte("[MASKED]")}
		}
	}
	return &apphook.Response{Action: apphook.ActionAllow}
}

// Status reports a CONSTANT Version across every swap below — that is the whole
// point: the detector binary never restarts when its packs change.
func (h *packSwapHook) Status() *apphook.Status {
	return &apphook.Status{Healthy: true, Version: "ai-compliance-detector/1.4.2 proto/4"}
}

// ContentVersion implements apphook.ContentVersioned.
func (h *packSwapHook) ContentVersion() (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.version, h.version != ""
}

// swap replaces the active ruleset AND the content version, like one pack pull.
func (h *packSwapHook) swap(version string, banned ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.banned = map[string]bool{}
	for _, b := range banned {
		h.banned[b] = true
	}
	h.version = version
}

func (h *packSwapHook) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

func sendTurn(t *testing.T, p *Proxy, content string) string {
	t.Helper()
	r := newReq(`{"messages":[{"role":"user","content":"` + content + `"}]}`)
	if proceed := p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "sess-packswap", "", discardLogger()); !proceed {
		t.Fatal("filter refused the request; these fixtures never block")
	}
	return readReqBody(t, r)
}

// TestFilterCache_RuleDeleteStopsMasking is the user's own acceptance criterion:
// the admin deleted the rule, so the very next turn must arrive unmasked.
//
// Pre-fix this test is RED: the cache key was detectorVersion|sha256(content),
// the detector version does not move on an in-place pack swap, and the sliding
// 1h TTL is refreshed on every hit — so a live conversation replays the stale
// mask forever ("我明明删了为什么还在打码").
func TestFilterCache_RuleDeleteStopsMasking(t *testing.T) {
	hook := newPackSwapHook("pack-v1", "ZQXJV770412")
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 50)

	if body := sendTurn(t, p, "my token is ZQXJV770412 ok"); !strings.Contains(body, "[MASKED]") {
		t.Fatalf("precondition: the rule must mask while it exists, got %q", body)
	}

	// Admin deletes the rule → pack version bumps → detector hot-swaps.
	hook.swap("pack-v2")

	body := sendTurn(t, p, "my token is ZQXJV770412 ok")
	if strings.Contains(body, "[MASKED]") {
		t.Fatalf("STALE MASK: the rule was deleted but the proxy replayed the cached mask verdict; body=%q", body)
	}
	if !strings.Contains(body, "ZQXJV770412") {
		t.Fatalf("content should pass through untouched after the rule was deleted; body=%q", body)
	}
	if hook.callCount() != 2 {
		t.Errorf("the swap must force a real re-scan: Detect calls = %d, want 2", hook.callCount())
	}
}

// TestFilterCache_RuleAddScansAlreadyCleanHistory covers the other direction —
// the one the old SAFETY CAVEAT comment worried about. History that was cached
// as clean must be re-scanned by a newly added rule, not ride the cache.
func TestFilterCache_RuleAddScansAlreadyCleanHistory(t *testing.T) {
	hook := newPackSwapHook("pack-v1") // empty ruleset: everything is clean
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 50)

	if body := sendTurn(t, p, "my token is ZQXJV770412 ok"); strings.Contains(body, "[MASKED]") {
		t.Fatalf("precondition: nothing masks with an empty ruleset, got %q", body)
	}

	// Admin adds a rule that covers content already sitting in the cache as clean.
	hook.swap("pack-v2", "ZQXJV770412")

	if body := sendTurn(t, p, "my token is ZQXJV770412 ok"); !strings.Contains(body, "[MASKED]") {
		t.Fatalf("STALE CLEAN: a newly added rule did not reach already-cached history; body=%q", body)
	}
}

// TestFilterCache_StableRulesetKeepsHitting is the counterweight: invalidation
// must key on the ruleset CHANGING, not on every request. Without this a "fix"
// that recomputes the epoch per request (or always misses) would pass the two
// tests above while silently turning the cache off — the cache exists because
// the history-leak fix re-scans every user message every turn.
func TestFilterCache_StableRulesetKeepsHitting(t *testing.T) {
	hook := newPackSwapHook("pack-v1", "SECRETPHRASE")
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 50)

	const turns = 20
	for i := 0; i < turns; i++ {
		sendTurn(t, p, "hello world this is turn content")
	}
	if hook.callCount() != 1 {
		t.Fatalf("hit rate collapsed: %d Detect calls over %d identical turns, want 1", hook.callCount(), turns)
	}
	perf := p.FilterPerformanceSnapshot()
	if perf.Incremental.Count != turns-1 {
		t.Errorf("incremental (cache-hit) lane = %d, want %d", perf.Incremental.Count, turns-1)
	}
}

// TestFilterCache_UnknownContentVersionBypassesCache — fail-safe, not
// fail-stale. If the hook cannot state which ruleset is live (child unreachable,
// first poll not back yet), the proxy must really scan every piece rather than
// keep serving verdicts minted under a ruleset that may no longer exist.
func TestFilterCache_UnknownContentVersionBypassesCache(t *testing.T) {
	hook := newPackSwapHook("pack-v1", "SECRETPHRASE")
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 50)

	sendTurn(t, p, "stable content")
	sendTurn(t, p, "stable content")
	if hook.callCount() != 1 {
		t.Fatalf("baseline: want 1 Detect call while the version is known, got %d", hook.callCount())
	}

	hook.swap("", "SECRETPHRASE") // version unknown, ruleset unchanged

	// READ side: an entry that was cached under a known version must not be
	// replayed while we can no longer confirm that version is still live.
	sendTurn(t, p, "stable content")
	sendTurn(t, p, "stable content")
	if hook.callCount() != 3 {
		t.Errorf("unknown ruleset must bypass the cache READ: Detect calls = %d, want 3", hook.callCount())
	}

	// WRITE side: content first seen DURING the unknown window carries no
	// attributable ruleset, so it must not become a cache entry that a recovered
	// version could inherit. Use content the cache has never seen, otherwise a hit
	// on a pre-existing (legitimately still-valid) entry would mask the bug.
	sendTurn(t, p, "content first seen while blind")
	before := hook.callCount()

	hook.swap("pack-v1", "SECRETPHRASE") // recovers to the SAME version as turn 1
	sendTurn(t, p, "content first seen while blind")
	if hook.callCount() != before+1 {
		t.Errorf("a verdict minted while the ruleset was unknown was cached and replayed under the recovered version: Detect calls = %d, want %d", hook.callCount(), before+1)
	}
}

// TestFilterCache_HookWithoutContentVersionStillCaches pins the tri-state: a
// hook that does NOT implement apphook.ContentVersioned has no hot-swappable
// content set, so there is nothing to invalidate and caching stays on exactly as
// before. Only "declares versioned content but cannot state it" disables the
// cache. Without this test the fail-safe branch above would be free to widen
// into "no interface → no cache", which silently disables the cache for every
// other AppHook.
func TestFilterCache_HookWithoutContentVersionStillCaches(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 50)

	sendTurn(t, p, "same content each turn")
	sendTurn(t, p, "same content each turn")
	if hook.called != 1 {
		t.Errorf("a hook with no versioned content must still be cacheable: Detect calls = %d, want 1", hook.called)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Fence + performance
// ─────────────────────────────────────────────────────────────────────────────

// TestFence_DispatchResolvesEpochThroughCacheEpoch keeps the dispatcher on the
// one sanctioned exit. Asserting the tri-state is handled correctly here is not
// enough: a future caller that type-asserts apphook.ContentVersioned itself will
// handle "known" and "not versioned" and drop "unknown" — the fail-safe branch,
// which is the one with no visible symptom in a green test run.
func TestFence_DispatchResolvesEpochThroughCacheEpoch(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	sawCacheEpoch := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		body := string(src)
		if strings.Contains(body, ".(apphook.ContentVersioned)") {
			t.Errorf("%s type-asserts apphook.ContentVersioned directly; call apphook.CacheEpoch instead", name)
		}
		if strings.Contains(body, "apphook.CacheEpoch(") {
			sawCacheEpoch = true
		}
	}
	if !sawCacheEpoch {
		t.Fatal("no caller of apphook.CacheEpoch left in this package — the verdict cache is no longer " +
			"invalidated by a ruleset swap (bugfix 20260813-pack-swap-does-not-invalidate-proxy-cache)")
	}
}

// TestFilterCache_PackSwapHitRateProfile is the counterweight to the correctness
// tests, in the shape of filter_cache_perf_test.go: it prints what the epoch
// costs on the hot path. Invalidation is only worth having if a STABLE ruleset —
// the state a deployment is in essentially all the time — still hits.
//
// Model: a growing conversation that resends its whole history every turn (the
// history-leak fix's scan pattern, which is why the cache exists at all), with
// ONE pack swap in the middle.
func TestFilterCache_PackSwapHitRateProfile(t *testing.T) {
	const turns = 50
	run := func(swapAt int) (detects int) {
		hook := newPackSwapHook("pack-v1", "NEVER-MATCHES-THIS")
		p := &Proxy{filterHook: hook}
		p.SetFilterCacheEnabled(true, defaultMaskCacheWindow)
		for turn := 1; turn <= turns; turn++ {
			if turn == swapAt {
				hook.swap("pack-v2", "NEVER-MATCHES-THIS")
			}
			var b strings.Builder
			b.WriteString(`{"messages":[`)
			for m := 1; m <= turn; m++ {
				if m > 1 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"role":"user","content":"message number %d"}`, m)
			}
			b.WriteString(`]}`)
			r := newReq(b.String())
			p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "sess-perf", "", discardLogger())
		}
		return hook.callCount()
	}

	noCache := turns * (turns + 1) / 2 // every piece of every turn, re-scanned
	stable := run(0)                   // no swap
	swapped := run(turns / 2)          // one swap halfway

	t.Logf("增长型对话 %d 轮(每轮 +1 新消息、历史全量重发),detector 真扫次数(越少越好):", turns)
	t.Logf("  无缓存                        : %4d", noCache)
	t.Logf("  缓存 + ruleset 稳定           : %4d  (省 %2.0f%%)", stable, 100*(1-float64(stable)/float64(noCache)))
	t.Logf("  缓存 + 第 %d 轮换一次 ruleset : %4d  (省 %2.0f%%,换库那轮全量重扫)", turns/2, swapped, 100*(1-float64(swapped)/float64(noCache)))

	// A stable ruleset must cost exactly one scan per distinct message — i.e. the
	// epoch changed nothing about steady-state hit rate.
	if stable != turns {
		t.Errorf("stable ruleset: %d detects over %d turns, want %d (one per distinct message) — the epoch is churning", stable, turns, turns)
	}
	// One swap costs exactly ONE re-scan of the history that was already cached,
	// and nothing beyond it: the swap turn re-scans its (swapAt-1) cached history
	// messages, while its own new message would have been scanned anyway. Every
	// later turn hits again under the new epoch. Anything larger means the epoch
	// keeps moving; anything smaller means a stale verdict survived the swap.
	wantSwapped := turns + (turns/2 - 1)
	if swapped != wantSwapped {
		t.Errorf("one swap: %d detects, want %d (%d baseline + %d already-cached history re-scanned once at the swap)",
			swapped, wantSwapped, turns, turns/2-1)
	}
}
