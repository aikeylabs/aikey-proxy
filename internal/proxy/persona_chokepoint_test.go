package proxy

// persona_chokepoint_test.go — §3.3 "归一真空" source-level fence (design
// 20260624-动态决策账号分配引擎-技术方案.md §3.3 / 不变量 7).
//
// THE RISK: a pooled (seat_group) account shares ONE account_uuid across N
// employees. Every OAuth-injection site that can serve a pooled account MUST
// route the OUTBOUND request through the AccountPersona normalization
// (stashPoolPersona → the Director's applyPoolPersonaFromContext). Miss one
// path and that path leaks the employee's REAL per-request identity (device_id /
// session / OS-arch / UA / metadata.user_id) under the shared account_uuid →
// "一号多设备 + session 暴涨" → ban. The design names the failure mode exactly:
// "漏接任一字段或任一代码路径即该路径未归一".
//
// THE INVARIANT THIS LOCKS: today every pooled OAuth request funnels through the
// SINGLE pool-serving chokepoint handleSeatGroupRoute (group_serve.go), which
// calls oauthInject AND immediately stashPoolPersona. The other oauthInject
// sites are single-account (non-pool) paths a pooled route can NEVER reach,
// because handle_dispatch.go:235 and pipelines.go:989 early-return pooled traffic
// (route.SeatGroupID != "") to handleSeatGroupRoute before those sites run.
//
// WHY A SOURCE-LEVEL FENCE (and what it adds over what exists):
//   - TestGroupServe_PoolPersonaUpstreamOnly proves the EXISTING funnel disguises
//     the outbound request — but it only exercises handleSeatGroupRoute, so a
//     brand-new pool-serving path that forgets the stash would not be exercised.
//   - poolOAuthLacksDisguise (the Director backstop) only emits a runtime WARN,
//     not a failing test.
//   This fence is the design's literal ask — "CI 围栏测试断言 oauthInject 调用点数
//   == Pooled 覆盖数". It goes RED the moment someone ADDS an oauthInject call in
//   a new function, forcing a conscious decision: does this path serve pooled
//   accounts? If so it must also stashPoolPersona. That is the "漏接一处" class of
//   regression nothing else here catches.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// knownOAuthInjectSites enumerates every function that calls oauthInject and
// whether it can serve a seat_group POOL account. A pool-serving site (true)
// MUST also call stashPoolPersona. Adding a new oauthInject site forces an update
// here — that is the review gate the fence creates.
var knownOAuthInjectSites = map[string]bool{ // enclosing func name -> servesPool
	// forward_and_resolve.go:224 — single personal_oauth_account binding. Non-pool:
	// ResolveBindingCredential resolves a 1:1 binding, not a seat_group.
	"ResolveBindingCredential": false,
	// pipelines.go:1132 (Tier1 OAuth token-route) + :1220 (Tier2 OAuth probe).
	// Non-pool: the SeatGroupID early-return (pipelines.go:989) dispatches pooled
	// traffic to handleSeatGroupRoute before either branch runs.
	"handlePathPrefixRoute": false,
	// group_serve.go:96 — the ONLY seat_group POOL funnel. Must also stash persona.
	"handleSeatGroupRoute": true,
}

func TestPersonaChokepoints_AllPoolInjectionRoutesThroughPersona(t *testing.T) {
	calls := callsByEnclosingFunc(t) // funcName -> set of identifier callees in its body

	// 1. Every function that injects OAuth must be a registered chokepoint, and
	//    every registered chokepoint must still inject — keep the fence honest
	//    against both additions (a new bypass path) and removals (drift).
	injecting := map[string]bool{}
	for fn, callees := range calls {
		if callees["oauthInject"] {
			injecting[fn] = true
		}
	}
	for fn := range injecting {
		if _, ok := knownOAuthInjectSites[fn]; !ok {
			t.Errorf("NEW oauthInject chokepoint %q is not registered in knownOAuthInjectSites.\n"+
				"  If this path can serve a seat_group POOL account it MUST also call stashPoolPersona,\n"+
				"  or pooled traffic reaches Anthropic with the employee's real identity under the\n"+
				"  shared account (归一真空 / §3.3 / 不变量 7). Register it here with the right servesPool flag.", fn)
		}
	}
	for fn := range knownOAuthInjectSites {
		if !injecting[fn] {
			t.Errorf("registered oauthInject chokepoint %q no longer calls oauthInject — "+
				"update knownOAuthInjectSites so the fence tracks the real call sites.", fn)
		}
	}

	// 2. Every POOL-serving chokepoint must also stash the persona disguise.
	for fn, servesPool := range knownOAuthInjectSites {
		if servesPool && !calls[fn]["stashPoolPersona"] {
			t.Errorf("pool-serving chokepoint %q calls oauthInject WITHOUT stashPoolPersona — "+
				"pooled traffic would reach the upstream carrying the employee's real identity under "+
				"the shared account_uuid (归一真空, ban risk). Add stashPoolPersona.", fn)
		}
	}
}

// callsByEnclosingFunc parses this package's NON-TEST sources and returns, for
// each FuncDecl, the set of identifier-call callees in its body. go/ast is used
// (not grep) so the many COMMENTS mentioning oauthInject do not count as calls.
func callsByEnclosingFunc(t *testing.T) map[string]map[string]bool {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate package source dir")
	}
	dir := filepath.Dir(thisFile)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package %s: %v", dir, err)
	}
	out := map[string]map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				callees := out[fd.Name.Name]
				if callees == nil {
					callees = map[string]bool{}
					out[fd.Name.Name] = callees
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if ce, ok := n.(*ast.CallExpr); ok {
						if id, ok := ce.Fun.(*ast.Ident); ok {
							callees[id.Name] = true
						}
					}
					return true
				})
			}
		}
	}
	return out
}
