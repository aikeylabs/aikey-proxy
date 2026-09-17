package app

// compliance_health_wiring_test.go — the hop no end-of-chain test can see.
//
// The compliance-policy health signal travels supervisor → admin.Handler → JSON,
// and every hop is hand-copied. A hop that is simply never wired produces no
// error anywhere: /health keeps answering 200, it is just permanently silent
// about a fleet enforcing a stale compliance ladder. That is the
// 「手工搬运的中转层会静默吞字段」 failure, and the rule there is explicit —
// fence the CHAIN, not the field. Task 3.8, R-compliance-grading-14.S2.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
	"github.com/AiKeyLabs/aikey-proxy/internal/supervisor"
)

// TestCompliancePolicyHealthIsWiredToAdmin checks the wiring function does what
// it says: after it runs, the admin handler can answer for the follower, and a
// supervisor that never polled reads as "no follower" rather than "healthy".
//
// 能红 check: point CompliancePolicyHealthFn at something else, or have
// ComplianceMasterPolicyHealth claim attempted=true before the first poll.
func TestCompliancePolicyHealthIsWiredToAdmin(t *testing.T) {
	h := &admin.Handler{}
	wireCompliancePolicyHealth(h, &supervisor.Supervisor{})
	if h.CompliancePolicyHealthFn == nil {
		t.Fatal("admin.Handler.CompliancePolicyHealthFn is nil after wiring — /health " +
			"would never report the compliance-policy follower")
	}
	rejects, attempted := h.CompliancePolicyHealthFn()
	if attempted || rejects != 0 {
		t.Fatalf("a supervisor that never polled must read as rejects=0 attempted=false, "+
			"got %d/%v", rejects, attempted)
	}
}

// TestCompliancePolicyHealthWiringIsReachedFromApp is the half the test above
// cannot cover: the test calls the wiring function itself, so deleting the CALL
// SITE in app.go leaves it green while every deployed proxy goes silent.
//
// Asserting on the source is deliberate. The alternative is standing up the
// whole application to observe one assignment, and the thing at risk here is not
// the assignment's behavior — it is whether anyone still makes it. Same posture
// as internal/proxy/hotpath_callgraph_fence_test.go.
//
// 能红 check: delete the wireCompliancePolicyHealth(...) line from app.go.
func TestCompliancePolicyHealthWiringIsReachedFromApp(t *testing.T) {
	const wiring = "wireCompliancePolicyHealth"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "app.go", nil, 0)
	if err != nil {
		t.Fatalf("parse app.go: %v", err)
	}
	called := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == wiring {
			called = true
		}
		return true
	})
	if !called {
		t.Fatalf("app.go never calls %s — the supervisor computes the compliance-policy "+
			"verdict and the admin handler knows how to render it, but nothing connects "+
			"them, so GET /health omits compliance_policy on every shipped proxy", wiring)
	}
}
