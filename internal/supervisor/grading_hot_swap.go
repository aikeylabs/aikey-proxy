// grading_hot_swap.go — TODO-188 方案 C: an org grading change is pushed into the
// RUNNING detector pool instead of re-spawning it.
//
// # What problem this solves
//
// The grading document used to reach the detector only as AIKEY_COMPLIANCE_GRADING
// at spawn, so every ladder / route_policy edit ran a full Reload: a new
// generation of M detectors next to the old M until the old one drained. On a
// 1.6 GB Cluster worker (M=2) the four detectors crossed the unit's MemoryHigh
// and the node livelocked — no OOM, no restart, ingress still sending it traffic
// (task-execution/runs/todo-188-triage.md). The swap keeps the processes: zero
// extra detectors for the most frequent policy change an administrator makes.
//
// # The decision table (用户拍板 2026-09-21; design todo-188-design.md §C.3 + §五)
//
//	every worker applied         → install the same bytes into this proxy
//	                               (escalation + route_policy, atomically), record
//	                               the new filter signature. Done, no reload.
//	any worker REFUSED           → the detector cannot read this document and
//	(parse_ok=false)               KEPT the previous one (C.7-3). Roll the workers
//	                               that did apply back to the previous bytes,
//	                               restore masterGrading, leave this proxy's rules
//	                               alone (R-compliance-grading-15: proxy and
//	                               detector read the same bytes), ERROR, /health
//	                               degraded. NO reload: a reload would spawn the
//	                               pool with the refused document in its env,
//	                               and a cold parse failure switches grading OFF
//	                               — the exact outcome the user rejected.
//	otherwise (an old detector,  → fall back to the pre-C full Reload; nothing
//	no answer, no pool)            was moved, masterGrading holds the new bytes.
//
// Ordering: detector first, proxy second. For the milliseconds in between the
// proxy's cumulative rule still uses the old document; R-compliance-grading-5.S1
// already promises no consistency inside a polling period.
//
// spec: R-compliance-grading-5.1
package supervisor

import (
	"bytes"
	"context"
	"log/slog"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// gradingEnvKey is the ONE spelling of the detector's grading variable: the
// spawn env (installFilterHook) and the hot swap's respawn-env rewrite
// (apphook.ChildHook.SetGrading) both name it through this constant.
const gradingEnvKey = "AIKEY_COMPLIANCE_GRADING"

// gradingSwapVerdict is what hotSwapGrading concluded. One enum so the caller's
// branch cannot disagree with the function's own decision.
type gradingSwapVerdict uint8

const (
	// gradingSwapApplied: the pool and this proxy enforce the new document.
	gradingSwapApplied gradingSwapVerdict = iota + 1
	// gradingSwapRefused: the detector refused it; everything stays on the
	// previous document and /health says so.
	gradingSwapRefused
	// gradingSwapNeedsReload: the caller must fall back to a full reload.
	gradingSwapNeedsReload
)

// hotSwapGrading pushes masterGrading (already swapped in by
// applyComplianceMasterPolicy) into the active generation. previous is the
// document in force before this poll.
//
// Holds reloadMu for the whole push, so a concurrent Reload (the 5s vault tick,
// a quota change) can neither spawn a pool mid-swap nor spawn one with a
// document the detector is about to refuse — it runs after, with masterGrading
// already restored on refusal.
func (s *Supervisor) hotSwapGrading(ctx context.Context, previous []byte) gradingSwapVerdict {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	next := s.gradingPolicyJSON()
	gen := s.active.Load()
	if gen == nil || gen.proxy == nil {
		return gradingSwapNeedsReload
	}
	pool, ok := gen.filterHook.(*apphook.FilterPool)
	if !ok {
		// No filter running (compliance off on this node) or a hook shape that
		// cannot be pushed to: the pre-C reload is the whole answer, and without
		// a detector it costs no extra process.
		return gradingSwapNeedsReload
	}

	results := pool.SetGrading(ctx, gradingEnvKey, next)
	applied, refused, other := tallyGradingPush(results)
	switch {
	case refused > 0:
		s.rollBackGradingSwap(ctx, pool, results, previous)
		streak := s.gradingHotSwapRefusals.Add(1)
		slog.Error("compliance grading change refused by the running detector; this node keeps "+
			"enforcing the previous document, which no longer matches the console. Upgrade the "+
			"detector or check the grading document the control plane serves",
			"event.name", observability.EventComplianceGradingHotSwapRefused,
			"error.code", observability.ErrCodeComplianceGradingRefusedByDetector,
			"workers", len(results), "refused", refused, "applied_then_rolled_back", applied,
			"refused_token", gradingComponent(next), "kept_token", gradingComponent(previous),
			"consecutive_refusals", streak)
		return gradingSwapRefused
	case other > 0:
		slog.Info("compliance grading hot swap not supported by every detector worker; falling back to a reload",
			"event.name", observability.EventComplianceGradingHotSwapFallback,
			"workers", len(results), "applied", applied, "unsupported_or_failed", other)
		return gradingSwapNeedsReload
	}

	// Every worker confirmed the exact bytes: now this proxy, from the same
	// bytes (R-compliance-grading-15), then the signature, so the next vault
	// tick does not see a "changed" grading term and reload anyway.
	logProxyGradingInstall(gen.proxy.SetComplianceGrading(next))
	if gen.vault != nil {
		if baseSig, ok := computeFilterSig(gen.vault); ok {
			sig := s.filterSigFrom(baseSig)
			s.lastFilterSig.Store(&sig)
		}
	}
	s.gradingHotSwapRefusals.Store(0)
	slog.Info("compliance grading hot-swapped into the running detector pool; no reload",
		"event.name", observability.EventComplianceGradingHotSwapped,
		"workers", len(results), "policy_token", gradingComponent(next))
	return gradingSwapApplied
}

// tallyGradingPush counts the three outcomes the decision table branches on.
func tallyGradingPush(results []apphook.GradingPushResult) (applied, refused, other int) {
	for _, r := range results {
		switch r.Outcome {
		case apphook.GradingPushApplied:
			applied++
		case apphook.GradingPushRefused:
			refused++
		case apphook.GradingPushUnsupported, apphook.GradingPushFailed:
			other++
		default:
			// A value this build does not know: treat it like "no usable answer"
			// (fall back to the reload), never like applied.
			other++
		}
	}
	return applied, refused, other
}

// rollBackGradingSwap returns every worker that DID apply the refused change to
// the previous document, and restores masterGrading — so the pool is uniform
// again and every later reload, crash-restart and signature check sees the
// document this node is actually enforcing. The workers that refused already
// kept the previous document. Called with reloadMu held.
func (s *Supervisor) rollBackGradingSwap(ctx context.Context, pool *apphook.FilterPool, results []apphook.GradingPushResult, previous []byte) {
	if !bytes.Equal(s.gradingPolicyJSON(), previous) {
		if len(previous) == 0 {
			s.masterGrading.Store(nil)
		} else {
			restored := append([]byte(nil), previous...)
			s.masterGrading.Store(&restored)
		}
	}
	workers := pool.Workers()
	for i, r := range results {
		if r.Outcome != apphook.GradingPushApplied || i >= len(workers) {
			continue
		}
		if back := workers[i].SetGrading(ctx, gradingEnvKey, previous); back.Outcome != apphook.GradingPushApplied {
			// The worker now enforces the refused-by-its-siblings document while
			// the others keep the previous one. Loud; per-worker content_version
			// on /v1/diagnostics/pipeline shows which one.
			slog.Error("compliance grading rollback failed on one detector worker; the pool is mixed until the next reload",
				"event.name", observability.EventComplianceGradingHotSwapRefused,
				"error.code", observability.ErrCodeComplianceGradingRefusedByDetector,
				"worker", i, "outcome", back.Outcome.String(), "error", back.Err)
		}
	}
}

// logProxyGradingInstall logs what proxy.SetComplianceGrading installed. Shared
// by the generation build (installFilterHook, the same bytes it baked into the
// detector env) and the hot swap (the same bytes every worker just confirmed) —
// two copies of these log lines would drift. The SetComplianceGrading call
// itself stays visible at each call site (installFilterHook's is pinned by
// TestEscalationRulesAreHandedToTheProxy). rule: R-compliance-grading-15
func logProxyGradingInstall(escRules int, refusedRules []string, gradingErr error) {
	if gradingErr != nil {
		// The document is not JSON at all. The last valid policy stays installed
		// (applyComplianceMasterPolicy never replaces a good document with an
		// unreadable one, R-compliance-grading-14), so this is loud but not fatal.
		slog.Warn("supervisor: org compliance grading document unreadable; escalation rules unchanged",
			"event.name", observability.EventComplianceGradingInvalid, "error", gradingErr)
	}
	for _, refused := range refusedRules {
		// 失败要显眼: an administrator configured a cumulative rule this proxy will
		// NOT carry out. Silently dropping it leaves them looking at a control on
		// the console that does nothing.
		slog.Warn("supervisor: escalation rule refused; it will NOT be enforced",
			"event.name", observability.EventComplianceEscalationRuleRefused, "rule", refused)
	}
	if escRules > 0 {
		slog.Info("supervisor: request-level compliance escalation active",
			"event.name", observability.EventComplianceEscalationRulesActive, "rules", escRules)
	}
}

// GradingHotSwapRefusals is the consecutive count of grading changes the
// running detector refused (0 = following). For GET /health.
func (s *Supervisor) GradingHotSwapRefusals() int {
	return int(s.gradingHotSwapRefusals.Load())
}
