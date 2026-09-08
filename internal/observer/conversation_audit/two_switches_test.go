package conversation_audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two switches, two subjects (阶段8 P13, tasks 13.C6 / 13.C7).
//
// An organisation has two independent controls, and the whole point is that
// neither one stands in for the other:
//
//	conversation_audit_enabled  whether prompts and replies are captured at all
//	MCP raw-arguments           whether TOOL ARGUMENT VALUES are retained
//
// # 🔴 Why these are fences and not behaviour tests
//
// Both failures are silent in the direction that matters. Wiring the MCP call
// log behind the conversation-audit switch means an organisation that turns off
// conversation capture — for privacy — ALSO loses its record of who called
// `delete_repo`, and nothing anywhere says so. Wiring tool arguments behind the
// conversation-audit switch means turning conversation capture ON starts
// retaining SQL, file contents and sometimes credentials through a control
// whose label says nothing about any of that (R16 / I14).
//
// A behaviour test would need both switches, both subsystems and a live org to
// demonstrate either. The shape is checkable here, at the seam where it would
// actually be broken.

// TestToolArgumentsDoNotFollowTheConversationAuditSwitch — task 13.C7 / R16.
//
// 🔴 Asserted STRUCTURALLY, following task 13.2b: there is no line in this file
// that can assign ArgsRaw, so the answer cannot depend on a condition somebody
// later gets wrong. "Reads the gate and finds it false" and "has no way to set
// the field" look identical in a passing test and are not the same guarantee —
// the first one is one refactor away from being true.
func TestToolArgumentsDoNotFollowTheConversationAuditSwitch(t *testing.T) {
	src, err := os.ReadFile("toolcalls.go")
	if err != nil {
		t.Fatalf("read toolcalls.go: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "toolcalls.go", src, 0)
	if err != nil {
		t.Fatalf("parse toolcalls.go: %v", err)
	}

	// Any assignment or composite-literal key naming ArgsRaw is a way in.
	var offenders []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "ArgsRaw" {
					offenders = append(offenders, fset.Position(x.Pos()).String())
				}
			}
		case *ast.KeyValueExpr:
			if k, ok := x.Key.(*ast.Ident); ok && k.Name == "ArgsRaw" {
				offenders = append(offenders, fset.Position(x.Pos()).String())
			}
		}
		return true
	})

	if len(offenders) > 0 {
		t.Errorf("🔴 toolcalls.go can now set ArgsRaw (%s).\n"+
			"Tool arguments are SQL, file contents and sometimes credentials. Their gate is the "+
			"MCP raw-arguments switch, NOT conversation_audit_enabled (R16 / I14) — one piece of "+
			"data behind two gates is no gate at all. Until this observer can read the MCP "+
			"switch, the fail-safe answer is the structural one: no line here may assign it.\n"+
			"判据一句话：读不到闸门 = 闸门是关的。", strings.Join(offenders, ", "))
	}

	// The positive half: the digest must still be produced, or this file has
	// simply stopped recording tool calls and the check above is vacuous.
	if !strings.Contains(string(src), "ArgsDigest") {
		t.Error("🔴 toolcalls.go no longer produces an argument DIGEST either. The rule is " +
			"'shape yes, values no', not 'nothing'")
	}
}

// TestTheMCPCallLogDoesNotReadTheConversationAuditSwitch — task 13.C6.
//
// 🔴 The two records answer different questions and are governed separately. An
// organisation that switches conversation capture off is saying "do not keep my
// developers' prompts"; it is NOT saying "stop recording which tools were
// invoked through the gateway". Collapsing the two would delete the security
// record as a side effect of a privacy setting — and the org would have no way
// to notice, because the absence of call records looks exactly like nobody
// having called anything.
func TestTheMCPCallLogDoesNotReadTheConversationAuditSwitch(t *testing.T) {
	// The MCP call record is built in a different package on purpose. If that
	// package ever grows a reference to this one's gate, the two have merged.
	mcpDir := filepath.Join("..", "..", "mcp")
	entries, err := os.ReadDir(mcpDir)
	if err != nil {
		t.Fatalf("read %s: %v", mcpDir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(mcpDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		// 🔴 Comments are stripped first: several files in that package discuss
		// the conversation audit in prose precisely to explain that they do not
		// depend on it, and a fence that fires on that explanation would be
		// asking for the explanation to be deleted.
		// 🔴 Case- and separator-insensitive. The first version listed only
		// `conversation_audit_enabled` and `ConversationAuditEnabled`, and its
		// own drill slipped straight past it: a Go variable holding that gate
		// would naturally be `conversationAuditEnabled`, which is the ONE
		// spelling the list did not have. A fence whose token list does not
		// cover the way the language actually spells things is a fence with a
		// hole exactly where the mistake would be made.
		code := strings.ToLower(strings.ReplaceAll(stripGoComments(string(b)), "_", ""))
		for _, gate := range []string{"conversationauditenabled", "conversationauditswitch"} {
			if strings.Contains(code, gate) {
				t.Errorf("🔴 %s reads %q. The MCP call log must not be gated on the "+
					"conversation-audit switch: an org that turns conversation capture off for "+
					"privacy would silently lose its record of who invoked which tool, and an "+
					"empty call log is indistinguishable from a quiet week", e.Name(), gate)
			}
		}
	}
}

// stripGoComments removes // and /* */ comments so token scans read code only.
func stripGoComments(src string) string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, parser.ParseComments)
	if err != nil {
		return src // unparseable: better to over-report than to skip silently
	}
	var b strings.Builder
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			b.WriteString(id.Name)
			b.WriteByte(' ')
		}
		if lit, ok := n.(*ast.BasicLit); ok {
			b.WriteString(lit.Value)
			b.WriteByte(' ')
		}
		return true
	})
	return b.String()
}
