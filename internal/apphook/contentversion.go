// contentversion.go — "which content set produced this verdict?"
//
// PROBLEM THIS SOLVES (2026-08-13, 用户: "删除之后，proxy 侧需要能够感知并且禁用该词库")
//
// A child app can hot-swap the content it detects against WITHOUT restarting:
// ai-compliance-detector pulls compliance packs on a timer and swaps its
// compiled ruleset atomically in place. Status().Version cannot see that — it is
// written once from the child's ready handshake and describes the BINARY.
//
// Anything that memoizes a child's verdicts therefore needs a second token that
// DOES move when the content moves. Without it the proxy's per-piece verdict
// cache (internal/proxy/filter_cache.go) keeps replaying verdicts minted under a
// ruleset that no longer exists — an admin deletes a rule on the console, the
// detector stops matching within ~1s, and the user still sees masked text
// because the proxy never re-asks. The sliding TTL makes it permanent for any
// conversation that stays alive, since every turn resends its history and every
// hit refreshes the entry's idle timer.
//
// WHY A FINGERPRINT OF THE EFFECTIVE-CONTENT REPORT, and not a declared field
// (the detector's pack cursor is right there in the same JSON):
//
//   - No new wire and no new field semantics. This layer keeps its contract with
//     the child at "hand me your effective-content report" (op=ListPacks, which
//     already exists and which the admin console already polls over the same
//     pipe); it hashes opaque bytes and never learns what a "pack" is. That is
//     the apphook.go invariant #16 — proxy must not know the child's business —
//     preserved rather than eroded.
//   - Strictly stronger than the cursor. The cursor only moves when the master
//     bumps a pack's distribution version; the report also carries rule counts,
//     phrase counts, dropped-rule lists and the active action policy. Any change
//     to what the child actually detects with changes the fingerprint, including
//     changes the cursor cannot express.
//   - Any future AppHook gets the same mechanism for free, with no per-app field
//     mapping to maintain.
//
// The cost is the poll interval: this is a bounded staleness window, not an
// event. See contentVersionPollInterval for why that is acceptable.
package apphook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// ContentVersioned is implemented by a Hook whose verdicts depend on a content
// set that can change while the child keeps running.
//
// Implementing it is a STATEMENT: "my verdicts can go stale without my process
// restarting, so do not memoize them without folding this token in".
type ContentVersioned interface {
	// ContentVersion returns an opaque token identifying the content set
	// currently effective in this hook, and false when it cannot be determined
	// (child unreachable, first poll not back yet, workers disagreeing).
	//
	// false means "unknown", never "unchanged" — callers MUST treat it as
	// "memoization is not permitted", never as "reuse the last token".
	ContentVersion() (string, bool)
}

// Compile-time proof that every FilterTarget implementation reports its content
// version. Kept next to the FilterTarget proofs in filterpool.go; the fence
// contentversion_fence_test.go fails if a new FilterTarget appears without a
// matching line here.
var (
	_ ContentVersioned = (*ChildHook)(nil)
	_ ContentVersioned = (*FilterPool)(nil)
)

// CacheEpoch is the ONE sanctioned way to ask "may I memoize this hook's
// verdicts, and under which epoch?". Callers must not type-assert
// ContentVersioned themselves — the tri-state below is the whole point and
// re-deriving it at each call site is how one of the three branches gets lost.
//
//	hook does not implement ContentVersioned → ("", true)
//	    No hot-swappable content, so there is nothing to invalidate. Caching stays
//	    on exactly as it was before this mechanism existed (apphook.Disabled, the
//	    degrade detector, test stubs).
//	hook implements it and knows its content set → (token, true)
//	    Fold token into the key. It changes ⇒ every entry keyed on the old one is
//	    unreachable ⇒ the swap invalidates itself, with no cache-flush plumbing.
//	hook implements it but cannot state it → ("", false)
//	    FAIL-SAFE, NOT FAIL-STALE: do not memoize and do not reuse. Re-scanning
//	    costs latency; replaying a verdict from a ruleset that may have been
//	    deleted costs correctness (the user sees masked text they un-banned, or
//	    unmasked text they just banned).
func CacheEpoch(h Hook) (epoch string, cacheable bool) {
	cv, ok := h.(ContentVersioned)
	if !ok {
		return "", true
	}
	v, known := cv.ContentVersion()
	if !known {
		return "", false
	}
	return v, true
}

const (
	// contentVersionPollInterval — how often each child is asked to restate its
	// effective content set.
	//
	// This is the proxy's share of the end-to-end "admin deletes a rule → the
	// user stops seeing it masked" latency. The detector's own pack poll is the
	// dominant term: the supervisor sets AIKEY_PACK_POLL_INTERVAL=60s
	// (filter_hook.go), so the child itself learns about the deletion up to 60s
	// late. Adding at most 15s on top keeps the total inside the same order of
	// magnitude while costing one bounded, lock-free IPC per child per 15s —
	// handleListPacks on the child side only reads a static manifest and one
	// atomic snapshot pointer, and the admin console already polls the very same
	// op over the very same pipe.
	//
	// Not env-tunable on purpose: a knob here would be a second, silent way to
	// widen a correctness window.
	contentVersionPollInterval = 15 * time.Second

	// contentVersionPollTimeout bounds one poll. Deliberately much larger than
	// the Detect deadline: a poll that gives up early would report "unknown" and
	// switch the caller's cache off for a busy-but-healthy child, which trades a
	// correctness problem we do not have for a latency problem we do.
	contentVersionPollTimeout = 5 * time.Second

	// contentVersionTokenLen — hex chars of the sha256 kept. 64 bits is ample for
	// an epoch token (it is compared for equality, never trusted as a security
	// boundary) and keeps the caller's cache keys short: this token is stored
	// inside every cached entry's key, up to maxSessions × window of them.
	contentVersionTokenLen = 16
)

// Why the content set is unknown. ENUMERATED, not free-form (日志规范: reasons
// live in a central enum, never as literals at the raise site) — these strings
// cross the process boundary on GET /v1/diagnostics/pipeline and drive which
// remedy `ak doctor` prints, so a typo would silently degrade a fix instruction
// into a shrug.
const (
	// ContentVersionReasonChildDegraded: the child is unreachable/wedged/crashed.
	// Its Detect calls fail open and are never cached anyway, so the disabled
	// cache is a symptom here, not the problem. Remedy: restart the proxy.
	ContentVersionReasonChildDegraded = "child_degraded"
	// ContentVersionReasonUnsupported: the child is ALIVE and answering Detect,
	// but returns an empty effective-content report — i.e. it does not implement
	// op=ListPacks. That is every detector build older than the 2026-08-13
	// pack-swap fix (bugfix 20260813-pack-swap-does-not-invalidate-proxy-cache).
	//
	// 🔴 The proxy's response — switch the verdict cache off entirely for this
	// node — is DELIBERATE and correct: a detector that cannot state which
	// ruleset it is using must not have its verdicts replayed, or a rule the
	// admin just deleted keeps masking. What was missing is that the cost (~96%
	// cache hit rate → 0, i.e. every content piece re-scanned every turn) was
	// invisible: operators saw only "the proxy got slower". Remedy: upgrade the
	// detector — this state ends the moment the child can answer op=ListPacks.
	ContentVersionReasonUnsupported = "unsupported_op_list_packs"
	// ContentVersionReasonPollPending: the child started but the first poll has
	// not returned yet. Self-clearing within contentVersionPollInterval; NOT a
	// fault, but still not cacheable.
	ContentVersionReasonPollPending = "first_poll_pending"
	// ContentVersionReasonPollFailed: the poll reached the child and failed for
	// some other reason (timeout, IPC error). Transient; the next tick retries.
	ContentVersionReasonPollFailed = "poll_failed"
)

// contentFingerprint reduces an app's self-reported effective-content report to
// a short token. Byte-identical reports ⇒ identical tokens, which is what makes
// a stable ruleset keep hitting the caller's cache.
func contentFingerprint(report []byte) string {
	sum := sha256.Sum256(report)
	return hex.EncodeToString(sum[:])[:contentVersionTokenLen]
}

// ─────────────────────────────────────────────────────────────────────────────
// ChildHook: one process, one content set
// ─────────────────────────────────────────────────────────────────────────────

// contentVersionState is the ONE place the "do I know my content set, and if
// not why?" rule lives. ContentVersion (the cacheability contract) and Status
// (the externally readable health projection) both derive from it, so the two
// can never disagree about whether this child is cacheable — a disagreement
// would show an operator "cache active" on the endpoint while the data plane
// re-scanned every piece.
//
// A degraded child reports unknown even if a fingerprint from before the failure
// is still in hand: its content set is exactly what we cannot vouch for, and the
// stored value is by definition the pre-failure one. (Its Detect calls fail open
// and are never cached anyway, so this costs nothing on the data plane.)
//
// token != "" ⇔ known. reason is populated iff token is "".
func (h *ChildHook) contentVersionState() (token, reason string) {
	if h.degraded.Load() {
		return "", ContentVersionReasonChildDegraded
	}
	if v := h.contentVersion.Load(); v != nil && *v != "" {
		return *v, ""
	}
	if r := h.contentVersionReason.Load(); r != nil && *r != "" {
		return "", *r
	}
	return "", ContentVersionReasonPollPending
}

// ContentVersion implements ContentVersioned.
func (h *ChildHook) ContentVersion() (string, bool) {
	v, _ := h.contentVersionState()
	return v, v != ""
}

// startContentVersionPoll launches the refresher once, on the first successful
// spawn. It outlives individual spawn generations on purpose: a restart replaces
// the pipe, not the content set, and the loop's own error handling already
// covers the window where the child is down.
func (h *ChildHook) startContentVersionPoll() {
	h.pollOnce.Do(func() { go h.contentVersionLoop() })
}

func (h *ChildHook) contentVersionLoop() {
	// Refresh immediately so the caller's cache is usable from the first request
	// rather than being fail-safe-disabled for a whole interval after startup.
	h.refreshContentVersion()
	t := time.NewTicker(contentVersionPollInterval)
	defer t.Stop()
	for {
		select {
		case <-h.pollStop:
			return
		case <-t.C:
			h.refreshContentVersion()
		}
	}
}

// refreshContentVersion polls the child once and publishes the result.
//
// Logging is transition-only (both directions) — a per-poll line would be 5760
// lines a day per child saying nothing changed, and the events that matter are
// "we can no longer tell" and "the content set moved under us".
func (h *ChildHook) refreshContentVersion() {
	// 🔴 OBSERVE, NEVER DRIVE (2026-08-13, found by TestChildHook_RestartRecovers
	// going ~50% flaky the moment this poll was added).
	//
	// roundtrip's first act on a degraded hook is `go h.lazyRecover()` — a
	// BACKGROUND RESPAWN. Without this guard the poll inherited that, and a
	// 15s timer silently became a restart trigger for the detector child:
	//
	//   - it raced operator- and dispatcher-initiated restarts (two concurrent
	//     restart() calls, the second killing a child the first had just handed a
	//     request to — that is exactly how the test failed: the frame went into a
	//     process that was killed before it could answer);
	//   - it changed respawn CADENCE for a broken child from "when a user request
	//     arrives" to "every 15s forever", including on an idle proxy with no
	//     traffic at all.
	//
	// Neither was asked for. This mechanism's entire job is to REPORT which
	// content set is live; the child's lifecycle belongs to Detect's self-heal
	// path and to the supervisor. A degraded child has no reportable content set
	// anyway (ContentVersion() returns unknown for it regardless), so skipping the
	// IPC loses nothing and costs the child nothing.
	if h.degraded.Load() {
		h.publishContentVersion(nil, errDegraded)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), contentVersionPollTimeout)
	defer cancel()
	h.publishContentVersion(h.listPacks(ctx, false))
}

// publishContentVersion turns one poll result into the published token. Split out
// so the "what does a failed poll do to the token?" rule has ONE implementation
// that tests drive directly — the alternative was a test re-stating the rule,
// which asserts the test's own copy rather than the code that ships.
func (h *ChildHook) publishContentVersion(report []byte, err error) {
	if err != nil || len(report) == 0 {
		reason := h.classifyContentVersionFailure(err)
		// Published BEFORE the transition check: the token and the reason must
		// never be observable in an inconsistent pair, and a repeat failure that
		// changes cause (degraded → recovered-but-too-old) has to update the
		// reason even though the token stayed nil.
		h.contentVersionReason.Store(&reason)
		if prev := h.contentVersion.Swap(nil); prev != nil {
			detail := "empty report"
			if err != nil {
				detail = err.Error()
			}
			// 失败要显眼: from here on the caller must re-scan everything, which is
			// safe but slower. An operator seeing sustained latency needs this line
			// to connect it to the child rather than to the LLM upstream.
			slog.Warn("apphook: child can no longer state its effective content set; verdict memoization disabled until it can",
				"event.name", observability.EventAppHookContentVersionUnknown,
				"name", h.cfg.Name, "reason", reason, "detail", detail)
		}
		return
	}

	v := contentFingerprint(report)
	h.contentVersionReason.Store(nil)
	prev := h.contentVersion.Swap(&v)
	if prev == nil || *prev != v {
		old := "(unknown)"
		if prev != nil {
			old = *prev
		}
		slog.Info("apphook: child effective content set changed; verdicts memoized under the previous one are now unreachable",
			"event.name", observability.EventAppHookContentVersionChanged,
			"name", h.cfg.Name, "previous", old, "current", v)
	}
}

// classifyContentVersionFailure maps one failed poll onto the enumerated reason
// an operator can act on.
//
// 🔴 THE DEGRADED CHECK MUST COME FIRST, and it re-reads the flag rather than
// trusting the error alone. listPacks converts errDegraded into the SAME
// ErrPacksUnavailable it returns for an empty report, so a child that degrades
// mid-poll (the flag was clear when refreshContentVersion checked it, and set by
// the time the roundtrip failed) would otherwise be labeled "too old" and be
// handed an upgrade instruction for what is actually a crash.
func (h *ChildHook) classifyContentVersionFailure(err error) string {
	switch {
	case errors.Is(err, errDegraded) || h.degraded.Load():
		return ContentVersionReasonChildDegraded
	case err == nil, errors.Is(err, ErrPacksUnavailable):
		// Alive, answered, and said nothing about its content set. listPacks maps
		// "child does not implement op=4 → empty report" onto ErrPacksUnavailable,
		// and err==nil with an empty report is the same condition reached from the
		// other branch of that function.
		return ContentVersionReasonUnsupported
	default:
		return ContentVersionReasonPollFailed
	}
}

// stopContentVersionPoll is idempotent — Shutdown is, so this must be too.
func (h *ChildHook) stopContentVersionPoll() {
	h.stopPollOnce.Do(func() { close(h.pollStop) })
}

// ─────────────────────────────────────────────────────────────────────────────
// FilterPool: M processes, M INDEPENDENT content sets
// ─────────────────────────────────────────────────────────────────────────────

// ContentVersion implements ContentVersioned for the pool.
//
// 🔴 THE POOL IS THE HARD CASE, AND IT IS NOT HYPOTHETICAL. Each worker runs its
// own pack puller against the master, so during propagation the workers really
// do hold different rulesets — and the caller cannot tell which worker served
// any given verdict (Detect is round-robin inside the pool; the wire carries no
// worker identity, and adding one would be a protocol change). Sampling worker 0
// and calling it "the pool's version" would leave every other worker's swap
// invisible, which is the original bug reintroduced at pool granularity.
//
// So the token is a COMPOSITE of every serving worker's token:
//
//   - Any single worker moving changes the composite ⇒ the caller's whole cache
//     is invalidated. Over-invalidating is the safe direction; the workers
//     converge within one pull interval and the composite settles.
//   - Order-independent (sorted): the pool is a set of interchangeable workers,
//     and round-robin position must not perturb the token.
//   - A worker that is healthy but cannot state its content set makes the WHOLE
//     pool unknown. It is serving traffic, so its verdicts can enter the cache,
//     and we cannot say under which ruleset.
//   - A degraded worker is skipped, not counted as unknown. It cannot contribute
//     cacheable verdicts (Detect fails open, and degraded responses are never
//     cached), so treating it as unknown would disable the cache for the whole
//     pool on account of a worker that cannot poison it. When it recovers, its
//     token re-enters the composite and the cache invalidates then.
//
// Why not "minimum cursor across workers", the other conservative aggregate: it
// requires the tokens to be ordered, which requires this layer to parse the
// child's report and understand its versioning scheme. The composite gets the
// same safety from equality alone. The price is one extra invalidation per
// convergence (the composite moves when the first worker updates and again when
// the last one does, where a minimum would move once) — rebuilding a cache that
// must be rebuilt anyway, on an event that happens when an admin edits a rule.
func (p *FilterPool) ContentVersion() (string, bool) {
	seen := make(map[string]struct{}, len(p.workers))
	tokens := make([]string, 0, len(p.workers))
	for _, w := range p.workers {
		v, ok := w.ContentVersion()
		if !ok {
			if w.Status().Healthy {
				return "", false // serving but unaccountable → fail-safe
			}
			continue // degraded → cannot contribute cacheable verdicts
		}
		// Deduplicated on purpose: the steady state is every worker holding the
		// SAME content set, and that state must be indistinguishable from a
		// single-worker pool holding it. Otherwise M would be baked into the token
		// and a converged 4-worker pool would key its cache differently from a
		// converged 1-worker pool for no reason — and, worse, convergence would
		// move the token twice (once when the first worker updates, once when the
		// last one does) even though the second move changes nothing observable.
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		tokens = append(tokens, v)
	}
	switch len(tokens) {
	case 0:
		return "", false
	case 1:
		// The common case (M=1 on Personal/Trial, and any converged pool): pass the
		// worker's own token through so it stays readable in logs and diagnostics.
		return tokens[0], true
	}
	sort.Strings(tokens)
	return contentFingerprint([]byte(strings.Join(tokens, "|"))), true
}
