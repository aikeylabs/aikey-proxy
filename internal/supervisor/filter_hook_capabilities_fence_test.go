package supervisor

// filter_hook_capabilities_fence_test.go — TODO-114 (需求包 roadmap20260320/
// 技术实现/阶段9-商业化版本/博时基金合规能力融合/task-execution/runs/
// design-todo-114.md §7.3③).
//
// 🔴 WHY SOURCE FENCES AND NOT BEHAVIORAL ONES. installFilterHook's spawn-SUCCESS
// path is only reached by the `integration`-tagged harness (a real CLI-migrated
// vault plus the real detector binary) — the same reason
// compliance_escalation_wiring_fence_test.go gives for its own shape. A test that
// called apphook.ProxyCapabilitiesEnv() itself would stay green with the
// production line deleted, which is precisely the false-green this file exists to
// avoid.
//
// WHAT THEY GUARD, in one sentence each:
//   - the declaration is HANDED DOWN, once, unconditionally (if it is ever put
//     inside a branch, the deployments that miss the branch hand the detector a
//     silent "I declare nothing" and personal-route counting stops there);
//   - the proxy never READS the declaration back from its own environment (a
//     capability is a property of this binary, and the moment configuration can
//     assert it, proxy.env / cluster-node.env can promise something the process
//     cannot do — the exact hole TODO-114 closes, entered from the inside).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const capabilitiesEnvFunc = "ProxyCapabilitiesEnv"

// TestInstallFilterHook_DeclaresProxyCapabilitiesExactlyOnce
func TestInstallFilterHook_DeclaresProxyCapabilitiesExactlyOnce(t *testing.T) {
	install := funcNamed(t, "filter_hook.go", "installFilterHook")

	// ① exactly one call in the whole function.
	var calls []*ast.CallExpr
	ast.Inspect(install, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == capabilitiesEnvFunc {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "apphook" {
				calls = append(calls, call)
			}
		}
		return true
	})
	if len(calls) != 1 {
		t.Fatalf("installFilterHook calls apphook.%s() %d times, want exactly 1.\n"+
			"0 ⇒ every detector this proxy spawns believes the proxy declares NOTHING, so the personal-route "+
			"count projection is never handed over and the organization's cumulative rule silently stops "+
			"counting personal-key traffic (TODO-114 / R-compliance-grading-24).\n"+
			">1 ⇒ two entries for one key, and which one the child reads depends on append order.",
			capabilitiesEnvFunc, len(calls))
	}

	// ② it is an element of the RESIDENT extraEnv composite literal, and that
	// literal's assignment is a direct statement of the function body — i.e. not
	// nested inside an `if` / `for` / `switch`. Checking the STATEMENT's position
	// in Body.List is stronger than hunting for enclosing branch nodes: anything
	// conditional necessarily lives in some other block.
	var assign *ast.AssignStmt
	for _, stmt := range install.Body.List {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		id, ok := as.Lhs[0].(*ast.Ident)
		if !ok || id.Name != "extraEnv" {
			continue
		}
		assign = as
		break
	}
	if assign == nil {
		t.Fatalf("no top-level `extraEnv := ...` statement in installFilterHook. The resident spawn-env " +
			"slice is where the capability declaration must live; re-point this fence, do not delete it.")
	}
	lit, ok := assign.Rhs[0].(*ast.CompositeLit)
	if !ok {
		t.Fatalf("`extraEnv :=` is no longer a composite literal (%T); this fence can no longer tell a "+
			"resident entry from a conditional append", assign.Rhs[0])
	}
	found := 0
	for _, elt := range lit.Elts {
		call, ok := elt.(*ast.CallExpr)
		if !ok {
			continue
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == capabilitiesEnvFunc {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("apphook.%s() appears %d times in the RESIDENT extraEnv literal, want exactly 1.\n"+
			"It must not be moved into a conditional append (`if masterURL != \"\"`, cluster-only, …): an "+
			"unconditional line is the ONLY thing that overrides an AIKEY_PROXY_CAPABILITIES value inherited "+
			"from ~/.aikey/proxy.env, /etc/aikey/cluster-node.env or a developer shell — ExtraEnv is appended "+
			"after os.Environ() and the last occurrence wins, so an omitted line means the residue is believed.",
			capabilitiesEnvFunc, found)
	}
}

// TestProxyNeverReadsCapabilitiesFromItsOwnEnvironment scans every non-test .go
// file under internal/ for a Getenv/LookupEnv on the capability env.
//
// WHY: the set must be derived from compiled Supports* predicates
// (apphook/capabilities.go). If the proxy could read it back, a deployment could
// tell the proxy to tell the detector that this binary can do something it
// cannot — which is worse than the release skew TODO-114 was opened for, because
// there at least the OLD side was honest. Same fence shape as the privacy tier's
// "READ THE ATOMIC, NEVER THE ENVIRONMENT … if this ever grows an os.Getenv
// fallback 'for testing', that is the fence gone" (filter_hook.go).
func TestProxyNeverReadsCapabilitiesFromItsOwnEnvironment(t *testing.T) {
	const envLiteral = `"AIKEY_PROXY_CAPABILITIES"`
	const envConst = "EnvProxyCapabilities"

	root := filepath.Join("..", "..", "internal")
	scanned := 0
	var offenders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // a file this parser cannot read is not evidence of a violation
		}
		scanned++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Getenv" && sel.Sel.Name != "LookupEnv") {
				return true
			}
			names := argNames(call.Args[0])
			for _, n := range names {
				if n == envLiteral || n == envConst {
					offenders = append(offenders,
						path+":"+fsetLine(fset, call.Pos())+" — "+sel.Sel.Name+"("+n+")")
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	// Anti-vacuity: a walk that found nothing because it visited nothing proves
	// nothing. internal/ carries hundreds of files.
	if scanned < 50 {
		t.Fatalf("scanned only %d non-test .go files under %s — the walk is broken and this fence is vacuous",
			scanned, root)
	}
	if len(offenders) > 0 {
		t.Fatalf("the proxy reads its OWN capability declaration back from the environment:\n  %s\n\n"+
			"A capability is a property of this BINARY — whether the decoding/serving code is linked in. "+
			"Deriving it from the environment lets ~/.aikey/proxy.env, /etc/aikey/cluster-node.env, the "+
			"Lobster de-proxy.env or a developer shell declare a capability the process does not have, and "+
			"the detector would then hand over bytes nothing can process. Derive it from Supports* "+
			"(internal/apphook/capabilities.go).", strings.Join(offenders, "\n  "))
	}
}

// argNames renders the spellings of a Getenv argument this fence recognizes: a
// string literal, or a selector/ident ending in the shared constant's name.
func argNames(arg ast.Expr) []string {
	switch a := arg.(type) {
	case *ast.BasicLit:
		return []string{a.Value}
	case *ast.Ident:
		return []string{a.Name}
	case *ast.SelectorExpr:
		return []string{a.Sel.Name}
	}
	return nil
}

func fsetLine(fset *token.FileSet, pos token.Pos) string {
	p := fset.Position(pos)
	return itoa(p.Line)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
