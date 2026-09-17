package proxy

// escalation_capability_skew_live_test.go — TODO-114's RELEASE-SKEW leg, run
// against the REAL ai-compliance-detector binary (需求包 roadmap20260320/技术实现/
// 阶段9-商业化版本/博时基金合规能力融合/task-execution/runs/design-todo-114.md §7.4;
// 用户 2026-09-15 拍板方案 A).
//
// # THE PROPERTY
//
// A NEW detector next to a proxy that does NOT declare `count_projection` hands
// back nothing on the personal route ⇒ the request is not refused by an
// accumulation, the counter reads zero, and no request-verdict row is written.
//
// # WHY IT NEEDS A REAL CHILD
//
// The two halves of the argument live in two repositories. The in-process fences
// prove each half separately (detector: undeclared ⇒ Event empty; proxy:
// TestEscalation_PersonalRouteMissingProjectionWarns: Event empty ⇒ warn, never
// refuse). Their JOIN is an env var crossing a process boundary, and every
// component of that join — the spelling, the append order in childhook.go, the
// detector's placement of the read ahead of its early returns — is invisible to
// both. This is the only test that fails if any one of them is wrong.
//
// 🔴 WHY THE NAME STARTS WITH TestApplyInboundFilter_LiveDetector:
// `make -f workflow/CI/Makefile p4-filter-live` selects by that PREFIX and routes
// the run through the compliance result gate with --fail-on-skip, so a vanished
// binary is RED there instead of a silently skipped test (the door in
// detector_door_test.go t.Skipf's on a bare `go test`). Renaming it off the prefix
// removes its only real observer.
//
// Run: make -f workflow/CI/Makefile p4-filter-live
//
// rules: R-compliance-grading-24 (收紧: 回传投影以 proxy 已声明为前提; S5 是它的反方向) ·
//        R-compliance-grading-6 (发布顺序 master → 控制台 → 探测器 → proxy)

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/pkg/pipewire"
)

// skewGradingDoc is the org document BOTH sides read — the proxy through
// SetComplianceGrading, the child through AIKEY_COMPLIANCE_GRADING — mirroring
// the production invariant that the ladder and the cumulative rule come from ONE
// document (supervisor/filter_hook.go: gradingEnvValue and SetComplianceGrading
// both read gradingPolicyJSON).
//
// WHY min_level 0 AND min_count 1: this fence is about the CARRIER, not about the
// ladder. A level floor would additionally require a tenant classification tree
// to be pulled from a pack master and a leaf to claim the built-in entity —
// machinery that belongs to R-compliance-grading-1's fences and that, if it broke,
// would make this test go green for the wrong reason (nothing counted because
// nothing was graded, not because the declaration was absent). `labels` is present
// so the document "declares something" and the child stamps level / confirmed at
// all (R-compliance-grading-6).
const skewGradingDoc = `{"labels":{"4":"商密"},"escalation":[{"min_level":0,"min_count":1,"action":"block"}]}`

// skewPrompt carries the two synthetic values TestApplyInboundFilter_LiveDetector
// proves the SHIPPED detector detects and masks — see that test for why these
// exact literals (a valid GB 11643 check digit; a phone outside the
// obvious-non-live veto list). Reusing them means a fixture-rot problem shows up
// there first, in the test that owns it.
const (
	skewIDCard = "110101199003077424"
	skewPhone  = "13857492631"
	skewPrompt = "请帮我核对客户手机号 " + skewPhone + "，身份证号 " + skewIDCard + " 是否正确"
)

// TestApplyInboundFilter_LiveDetector_UndeclaredProxyNoProjectionNotRefused
func TestApplyInboundFilter_LiveDetector_UndeclaredProxyNoProjectionNotRefused(t *testing.T) {
	bin, sealed := liveDetectorBinary(t, "the TODO-114 capability-skew live fence")

	// The developer's own shell must not be able to declare on the proxy's behalf:
	// ExtraEnv is appended after os.Environ(), so an inherited value would be
	// overridden in the DECLARED arm but silently believed in the UNDECLARED one.
	t.Setenv(pipewire.EnvProxyCapabilities, "")

	// One arm = one child process, differing ONLY in whether the capability line is
	// in ExtraEnv. Everything else — binary, grading document, prompt, rule — is
	// shared, so the declaration is the single independent variable.
	type arm struct {
		name     string
		extraEnv []string
	}
	capabilityLine := apphook.ProxyCapabilitiesEnv()
	if capabilityLine == pipewire.EnvProxyCapabilities+"=" {
		t.Fatal("this proxy build declares NO capability; the declared arm below would be identical to " +
			"the undeclared one and the whole fence would be vacuous")
	}

	startHook := func(t *testing.T, a arm) *apphook.ChildHook {
		t.Helper()
		hook := apphook.NewChildHook(&apphook.ChildHookConfig{
			Name:       "ai-compliance-detector",
			BinaryPath: bin,
			// Generous: real CRF NER on a full prompt is far above the 1ms default,
			// and a timeout fails OPEN (no verdict), which would make the undeclared
			// arm pass for the wrong reason.
			Timeout:      5 * time.Second,
			ReadyTimeout: 30 * time.Second,
			ExtraEnv:     a.extraEnv,
		})
		if err := hook.Start(context.Background()); err != nil {
			t.Fatalf("[%s] spawn detector: %v", a.name, err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = hook.Shutdown(ctx)
			cancel()
		})
		sealed.AssertHeld(t, hook)
		return hook
	}

	gradingEnv := "AIKEY_COMPLIANCE_GRADING=" + skewGradingDoc
	undeclared := arm{name: "undeclared (an OLD proxy)", extraEnv: []string{gradingEnv}}
	declared := arm{name: "declared (THIS proxy)", extraEnv: []string{gradingEnv, capabilityLine}}

	// ── ① the carrier itself, observed directly on the pipe ──────────────────
	//
	// Asserted before any request-level behavior so a failure names the hop that
	// broke rather than its downstream consequence.
	probe := func(t *testing.T, hook *apphook.ChildHook) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		res := hook.Detect(ctx, &apphook.Request{
			Direction:  apphook.DirectionInbound,
			Payload:    []byte(skewPrompt),
			RouteClass: apphook.RouteClassPersonal,
		})
		if res.Degraded {
			t.Fatalf("child degraded (%s); a degraded child returns no Event for an unrelated reason "+
				"and this fence would be measuring the timeout, not the gate", res.Reason)
		}
		if res.Action == apphook.ActionAllow {
			t.Fatalf("the detector found nothing in the fixture prompt (action=%s). Without a finding "+
				"there is no projection to withhold and every assertion here is vacuous — the fixture "+
				"has rotted; see TestApplyInboundFilter_LiveDetector, which owns these literals.",
				res.Action)
		}
		return res.Event
	}

	undeclaredHook := startHook(t, undeclared)
	declaredHook := startHook(t, declared)

	if ev := probe(t, undeclaredHook); len(ev) != 0 {
		t.Errorf("the UNDECLARED arm was handed %d bytes on the personal route: %s\n"+
			"An old proxy decodes this with the same `findings` decoder it uses on a team event and can "+
			"refuse the request on the cumulative rule — while writing the request-verdict row only on the "+
			"TEAM branch. The customer sees a refusal that nothing anywhere explains (TODO-114).",
			len(ev), ev)
	}
	declaredProjection := probe(t, declaredHook)
	if len(declaredProjection) == 0 {
		t.Fatal("the DECLARED arm got no projection either. Either the declaration is not reaching the " +
			"child (spelling / childhook append order / the detector's read placed after an early return), " +
			"or the projection feature is broken. Without this arm the test above proves nothing: 'no " +
			"bytes' would be true for a detector that never projects at all.")
	}

	// ── ② the consequence a customer sees ────────────────────────────────────
	runRequest := func(t *testing.T, hook *apphook.ChildHook) (proceed bool, code int, counted, triggered int, verdicts int) {
		t.Helper()
		sinks := newRouteSinks(t)
		p := &Proxy{filterHook: hook, reporter: sinks.rep}
		applied, rejected, err := p.SetComplianceGrading([]byte(skewGradingDoc))
		if err != nil || len(rejected) > 0 || applied != 1 {
			t.Fatalf("SetComplianceGrading(%s): applied=%d rejected=%v err=%v", skewGradingDoc, applied, rejected, err)
		}
		w := httptest.NewRecorder()
		r := newReq(`{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":` +
			mustJSON(t, skewPrompt) + `}]}`)
		proceed = p.applyInboundFilter(w, r, "claude-3-5-sonnet", "personal", "", personalVK, "", "sess-skew",
			"trace-todo114-skew", discardLogger())
		esc := p.escalationSnapshot()
		// The verdict row is written asynchronously; give it the same window the
		// TODO-87 fences use before concluding there is none.
		verdicts = len(batchesWithin(sinks.local, 1500*time.Millisecond))
		if team := batchesWithin(sinks.team, 100*time.Millisecond); len(team) != 0 {
			t.Errorf("the TEAM sink received %d request(s) for a personal-route request", len(team))
		}
		return proceed, w.Code, esc.counted, esc.triggered, verdicts
	}

	t.Run("undeclared_proxy_not_refused_no_verdict_row", func(t *testing.T) {
		proceed, code, counted, triggered, verdicts := runRequest(t, undeclaredHook)
		if !proceed {
			t.Errorf("the request was REFUSED (status %d) against a proxy that declared nothing. That is "+
				"the TODO-114 defect itself: refused by an accumulation the audit trail cannot explain.",
				code)
		}
		if counted != 0 || triggered != 0 {
			t.Errorf("counted/triggered = %d/%d, want 0/0 — with no projection there is nothing to count",
				counted, triggered)
		}
		if verdicts != 0 {
			t.Errorf("%d local batch(es) written; an unrefused request writes no request-verdict row", verdicts)
		}
	})

	t.Run("declared_proxy_counts_and_refuses", func(t *testing.T) {
		// 🔴 ANTI-VACUITY ARM. If this one does not trigger, the arm above proves
		// nothing: "not refused" would be true because the fixture cannot reach the
		// threshold at all, not because the declaration was withheld.
		proceed, code, counted, triggered, verdicts := runRequest(t, declaredHook)
		if counted == 0 {
			t.Fatalf("the DECLARED arm counted 0 hits, so the undeclared arm's 'not refused' is vacuous. "+
				"The projection reached the proxy (%d bytes on the pipe) but nothing in it satisfied the "+
				"rule %s — check Confirmed (the evidence gate's verdict) and the category filter "+
				"(countsTowardEscalation excludes `secret`).", len(declaredProjection), skewGradingDoc)
		}
		if triggered != 1 {
			t.Errorf("triggered = %d, want 1 (min_count is 1 and %d hits counted)", triggered, counted)
		}
		if proceed || code != http.StatusForbidden {
			t.Errorf("declared arm: proceed=%v status=%d, want refused with 403 — the org's cumulative rule "+
				"must fire on a member's personal key (R-compliance-grading-24.S1)", proceed, code)
		}
		if verdicts == 0 {
			t.Error("no request-verdict row on the local self-view for a refused personal-route request " +
				"(R-compliance-grading-24.S1); the whole point of the gate is that a refusal is explainable")
		}
	})
}
