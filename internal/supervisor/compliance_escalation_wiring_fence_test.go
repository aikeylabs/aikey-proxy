package supervisor

import (
	"go/ast"
	"go/token"
	"testing"
)

// Fence for the supervisor half of task 3.11: the org escalation rules must
// actually be HANDED to the proxy.
//
// 🔴 WHY A SOURCE FENCE AND NOT A BEHAVIORAL ONE. The call lives on
// installFilterHook's spawn-SUCCESS path, and the only test in this package that
// reaches that path is filter_max_action_integration_test.go (build tag
// `integration`: a real CLI-migrated vault plus the real detector binary). A
// unit-level behavioral fence would need that same harness. The alternative
// that looks cheaper — a test that calls p.SetComplianceGrading itself — is the
// false-green shape task 3.8 caught in its own first draft: it stays green with
// the production call site deleted. So this asserts on the call site, reusing
// funcNamed / callsMethodOn from observer_teardown_fence_test.go.
//
// WHAT IT GUARDS: steps 1–3 of DEC-compliance-grading-11 were green for days
// while being unreachable. The proxy-side fences (internal/proxy
// escalation_wiring_test.go) prove the dispatcher uses the rules it is given;
// this proves somebody gives them. Without this line every production proxy
// evaluates zero rules on every request and nothing anywhere reports it.
//
// BOUNDARY, stated out loud: this proves the call exists and reads the same
// accessor the detector env reads. It does not prove the call is on the success
// path rather than, say, inside a dead branch — that is what the integration
// harness above would add.
//
// rule: R-compliance-grading-15 (task 3.11)
func TestEscalationRulesAreHandedToTheProxy(t *testing.T) {
	install := funcNamed(t, "filter_hook.go", "installFilterHook")

	if !callsMethodOn(install, "p", "SetComplianceGrading") {
		t.Fatal("installFilterHook no longer calls p.SetComplianceGrading(...). The org's " +
			"`escalation[]` rules then never reach the proxy: every request evaluates zero rules, " +
			"no cumulative block ever fires, and nothing reports it — the console keeps showing a " +
			"configured control that does nothing (R-compliance-grading-15).")
	}

	// Same bytes as the detector env, or the two readers can enforce different
	// policies. gradingEnvValue (the env) and SetComplianceGrading must both read
	// gradingPolicyJSON — one document, two readers, each modeling its own member.
	var arg ast.Expr
	ast.Inspect(install, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "SetComplianceGrading" && len(call.Args) == 1 {
			arg = call.Args[0]
			return false
		}
		return true
	})
	inner, ok := arg.(*ast.CallExpr)
	if !ok {
		t.Fatalf("p.SetComplianceGrading must be passed s.gradingPolicyJSON() directly; got %T", arg)
	}
	sel, ok := inner.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "gradingPolicyJSON" {
		t.Fatalf("p.SetComplianceGrading is fed something other than s.gradingPolicyJSON(). The " +
			"detector child receives that exact document as AIKEY_COMPLIANCE_GRADING; feeding the " +
			"proxy from any other source lets the ladder and the cumulative rule come from two " +
			"different policies.")
	}
}

// TestEscalation_MaxActionReachesProxyFromSupervisor is the call-site fence for
// task 3.13: the proxy's request-level escalation ceiling must be fed the SAME
// MAX_ACTION value the detector child receives as
// AIKEY_COMPLIANCE_FILTER_MAX_ACTION.
//
// WHY "THE SAME VALUE" IS THE ASSERTION, not merely "the setter is called": the
// per-piece verdicts are capped inside the detector and the cumulative verdict
// is capped inside the proxy. If the two are fed from two reads — the proxy
// re-reading the environment, or the vault a second time — an operator's
// MAX_ACTION=warn can hold on one side and not the other, which is exactly the
// outage this task closes (the cumulative rule refusing a request the operator
// said to only warn on). So this asserts that both uses are the SAME declared
// variable, and that nothing reassigns it after the env line is built.
//
// Source fence rather than behavioral, for the reason the fence above spells
// out: the call sits on installFilterHook's spawn-SUCCESS path, which only the
// `integration`-tagged harness reaches.
//
// rule: R-compliance-grading-15 (task 3.13)
func TestEscalation_MaxActionReachesProxyFromSupervisor(t *testing.T) {
	const envPrefix = `"AIKEY_COMPLIANCE_FILTER_MAX_ACTION="`
	install := funcNamed(t, "filter_hook.go", "installFilterHook")

	if !callsMethodOn(install, "p", "SetComplianceMaxAction") {
		t.Fatal("installFilterHook does not call p.SetComplianceMaxAction(...). The detector caps each " +
			"piece at MAX_ACTION, but the proxy's cumulative escalation never learns the value and keeps " +
			"refusing whole requests while the operator has set MAX_ACTION=warn (R-compliance-grading-15: " +
			"升级后的动作 SHALL 受请求级天花板 MAX_ACTION 钳制).")
	}

	// The variable the detector env is built from.
	var envVar *ast.Ident
	var envPos token.Pos
	ast.Inspect(install, func(n ast.Node) bool {
		be, ok := n.(*ast.BinaryExpr)
		if !ok || be.Op != token.ADD {
			return true
		}
		if lit, ok := be.X.(*ast.BasicLit); ok && lit.Value == envPrefix {
			if id, ok := be.Y.(*ast.Ident); ok {
				envVar, envPos = id, be.Pos()
			}
		}
		return true
	})
	if envVar == nil || envVar.Obj == nil {
		t.Fatalf("could not find `%s + <variable>` in installFilterHook — the detector env is no longer "+
			"built from a single variable, so this fence cannot prove the proxy gets the same value. "+
			"Re-point it; do not delete it.", envPrefix)
	}

	// The argument handed to the proxy.
	var arg ast.Expr
	var callPos token.Pos
	ast.Inspect(install, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "SetComplianceMaxAction" && len(call.Args) == 1 {
			arg, callPos = call.Args[0], call.Pos()
			return false
		}
		return true
	})
	id, ok := arg.(*ast.Ident)
	if !ok || id.Obj == nil || id.Obj != envVar.Obj {
		t.Fatalf("p.SetComplianceMaxAction is fed %#v, not the variable `%s` the detector env "+
			"AIKEY_COMPLIANCE_FILTER_MAX_ACTION is built from. Two sources mean the per-piece cap and the "+
			"request-level cap can disagree.", arg, envVar.Name)
	}

	// No reassignment after the env line: otherwise "the same variable" can still
	// hold two different values at the two uses.
	ast.Inspect(install, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range as.Lhs {
			if l, ok := lhs.(*ast.Ident); ok && l.Obj == envVar.Obj && as.Pos() > envPos {
				t.Errorf("`%s` is reassigned after the detector env is built (and the proxy call is at %v): "+
					"the proxy could receive a different MAX_ACTION than the detector.", envVar.Name, callPos)
			}
		}
		return true
	})
}
