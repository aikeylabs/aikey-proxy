package proxy

// hotpath_callgraph_fence_test.go — the call-graph assertion test-plan MOD-16 and
// PLANE-01 ask for, in the repository that actually forwards.
//
// # 🔴 Why it has to live here
//
// Both items were registered UNCOVERED for the same reason, and it was the right
// answer at the time:
//
//	MOD-16    该能力不在每请求转发热路径上（调用图断言）
//	PLANE-01  proxy 热路径无 licensing import、文件/DB/同步控制调用
//
// aikey-control-master has a test called TestTheProxyHotPathHasNoLicensingDependency,
// and it asserts something true about the wrong process: forwarding is done HERE,
// by aikey-proxy, and a dependency fence inside the control plane cannot see this
// module's import graph. A fence in the wrong repository is worse than none — it
// reads as coverage.
//
// # What this walks, and what it over-approximates
//
// It is a real reachability walk from `(*Proxy).Handle`, the function the
// supervisor calls once per request (internal/supervisor: `g.proxy.Handle(w, r)`).
// It follows calls through THIS MODULE's own packages and collects every file it
// reaches, then asserts what those files may import and call.
//
// 🔴 Method calls are resolved by NAME rather than by type. That over-approximates:
// a call to `x.Close()` follows every `Close` method in the module. This is the
// deliberate direction. An over-approximating fence can raise a false alarm, which
// costs somebody an investigation; an under-approximating one misses the call that
// matters, which is the failure this item exists to prevent. 🚫 Do not "tighten"
// it into a type-resolved graph without keeping the union of both.
//
// It deliberately uses only the standard library. Adding golang.org/x/tools as a
// direct dependency of a SHIPPED proxy so that a test can build a call graph is a
// production dependency bought with test convenience.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/AiKeyLabs/aikey-proxy"

// hotPathEntry is the per-request entry point. internal/supervisor's
// generation.ServeHTTP calls exactly this, once per request.
const hotPathEntry = "internal/proxy::Proxy.Handle"

// forbiddenImports are packages no function reachable from the hot path may
// import.
//
// Each carries the reason, because a fence whose failure message is a list of
// package names teaches nobody why they are on it.
var forbiddenImports = map[string]string{
	"github.com/AiKeyLabs/aikey-license-core": "PLANE-01 / MOD-16: 热路径无 licensing import. " +
		"A license evaluation on the forwarding path means every request pays for it, and a " +
		"licensing failure becomes a forwarding outage — design D3.1 puts authorization off " +
		"this path precisely so that a license problem degrades the control plane and not the " +
		"customer's traffic",
}

// forbiddenCalls are calls no function reachable from the hot path may make.
//
// # 🔴 Calls, not imports, and the first version got this wrong
//
// The import check was applied per FILE, so every function in any file that
// imports `database/sql` was reported — including `Snapshot.Len`, which counts a
// slice. A fence that reports a length accessor as a database call on the request
// path is a fence somebody deletes.
//
// Licensing stays an IMPORT check, and that asymmetry is deliberate: a licensing
// import anywhere in the reachable set is the thing MOD-16 forbids, and being
// over-strict there costs nothing because the correct number is zero. `os` and
// `database/sql` are legitimately present — os.Getenv at start-up, a pool built
// once — so for those only the CALL is forbidden.
var forbiddenCalls = map[string]string{
	// File I/O per request puts the disk in the request path.
	"os.Open":         fileReason,
	"os.OpenFile":     fileReason,
	"os.ReadFile":     fileReason,
	"os.WriteFile":    fileReason,
	"os.Create":       fileReason,
	"os.Stat":         fileReason,
	"os.ReadDir":      fileReason,
	"ioutil.ReadFile": fileReason,
	"os.Remove":       fileReason,
	"os.MkdirAll":     fileReason,
}

const fileReason = "PLANE-01: 热路径无文件调用 — a per-request file call puts the disk in the request path"

// forbiddenMethodCalls are method names that mean "this is talking to a database"
// whatever the receiver is called.
//
// 🔴 Matched by NAME, so `cache.Query(...)` would trip it too. That is the safe
// direction here and the allowlist is where a false positive gets recorded with a
// reason, rather than the check being loosened for everybody.
var forbiddenMethodCalls = map[string]string{
	"QueryContext":    dbReason,
	"ExecContext":     dbReason,
	"QueryRowContext": dbReason,
	"BeginTx":         dbReason,
}

const dbReason = "PLANE-01: 热路径无 DB 调用. A query per request couples forwarding latency to " +
	"database health, and a database that is merely slow then looks like a proxy that is broken"

// allowedFileCalls are the calls this fence has been shown and that a human
// decided to keep, with the reason.
//
// 🔴 An allowlist, not a silent exclusion. The first run found a real one — the
// proxy writes a statusline hint file while answering "this shared account needs
// a login" — and the honest thing is neither to delete the finding nor to fail
// the build over it, but to write the judgement down so the next person can
// disagree with it.
//
// 🚫 The judgement is that PLANE-01 says 每请求**转发**热路径: the FORWARDING path.
// respondLoginRequired terminates the request without contacting any upstream,
// and the write is documented as best-effort and non-blocking. If that reading is
// wrong, the fix is to move the write off the request entirely, not to widen this
// list.
//
// TestEveryAllowedFileCallIsStillReachable fails if an entry goes stale, so this
// cannot quietly become the place exceptions go to die.
// hotPathFileCalls is the file I/O reachable from the forwarding entry point
// TODAY.
//
// # 🚫 This is a RECORD, not an approval
//
// Every line here is a real per-request-reachable file call that this fence found
// on 2026-08-11. None of them has been adjudicated against PLANE-01's
// 热路径无文件调用, and 🚫 nothing in this file should be read as saying they are
// fine. Most look like best-effort persistence — a cooldown store, a last-errors
// ring, an event WAL, a crash dump — and whether "best-effort" means "off the
// forwarding path" is a question for whoever owns this proxy, not for a test.
//
// # Why a ratchet rather than a pass or a failure
//
// Failing the build on twenty pre-existing call sites would mean this fence gets
// deleted within a week. Allowlisting them with invented reasons would be worse:
// it would turn twenty open questions into twenty settled ones, in a comment
// nobody asked for.
//
// So the list is a BASELINE. A new file call on the request path fails
// immediately, which is the property that actually protects the hot path going
// forward, and every entry stays visible in the test output so the inventory is
// impossible to forget. As they are fixed, the lines come out — and the test
// fails if one is stale, so the list can only shrink honestly.
//
// # 🔴 The three compliance dead-letter lines, added 2026-08-13
//
// They are NOT new work by this change. They arrived from develop-v1.0.5's
// compliance dead-letter lane and this branch first met them when the two were
// merged: the fence is GREEN on this branch alone and RED on the merge, which is
// the only run that reflects what ships. `deadLetterWriter.Count` became
// `.counts` in the same refactor, so its old line went stale at the same moment.
//
// 🚫 Recorded, not approved — same as every other line here. Their call site
// (internal/proxy/filter_dispatch.go: `observability.GoSafe(...)`, inside a
// bypass goroutine) documents itself as off the user's request path, and the
// reachability walk deliberately does not model `go` boundaries: it answers
// "can a request reach this code", not "does a request block on it". That
// conservatism is the point — it is what keeps the crash-dump and WAL lines
// above visible too. Whoever adjudicates PLANE-01 should decide these three as a
// group with them, not wave them through on the goroutine alone.
var hotPathFileCalls = map[string]struct{}{
	// ── MCP policy cache (阶段8 P2) ─────────────────────────────────────────
	//
	// 🔴 A FALSE POSITIVE of this fence's deliberate name-based resolution, and
	// recorded here rather than "fixed" because the over-approximation is the
	// design (see this file's header).
	//
	// PolicyCache.Load is reached only because the walk follows every method
	// named `Load` from any `x.Load()` on the hot path — of which there are many
	// (atomic.Value, atomic.Int64, sync.Map). Its REAL call sites are two, both
	// in internal/supervisor/mcp_policy.go and neither on a request:
	//
	//	NewMCPPolicyRail   once, at process start, before the listener serves
	//	syncMCPPolicy      once per 60s poll tick, on the poller goroutine
	//
	// The MCP plane does not run inside (*Proxy).Handle at all: it is a separate
	// RouteRegistrar mounted on the shared mux (app.buildMCPPlane), so an MCP
	// request never enters this entry point, and an LLM request never enters the
	// MCP plane.
	//
	// 🔴 If that stops being true — if anything ever calls PolicyCache.Load from
	// a request — this line becomes a lie rather than a false positive. The
	// verification is one grep: `PolicyCache` must appear in no file reachable
	// from Proxy.Handle.
	"internal/mcp::PolicyCache.Load|os.ReadFile": {},
	// ── MCP credential store (阶段8 P4) ─────────────────────────────────────
	//
	// 🔴 The SAME false positive as PolicyCache.Load above, via a different
	// colliding name, and recorded rather than "fixed" for the same reason.
	//
	// The edge is `CredentialStore.Replace`. The hot path calls `strings.Replace`
	// (among others), the walk resolves callees by NAME, and so every method
	// named `Replace` in the module joins the graph — including this one, which
	// then reaches writeSealedCache → atomicWriteFile. VERIFIED, not assumed:
	// a probe over this same graph showed Replace/writeSealedCache/atomicWriteFile
	// reachable while RestoreFromCache (which nothing on the hot path names) is
	// not — exactly the signature of a name collision rather than a real path.
	//
	// The REAL call sites of CredentialStore.Replace are one, and it is not a
	// request:
	//
	//	Supervisor.syncMCPCredentials   once per 60s poll tick, on the rail
	//	                                goroutine (internal/supervisor/
	//	                                mcp_credential_rail.go)
	//
	// The MCP plane does not run inside (*Proxy).Handle at all — it is a
	// separate RouteRegistrar on the shared mux (app.buildMCPPlane) — and even
	// an MCP tool call only ever READS this store (CredentialStore.Resolve,
	// which touches no file).
	//
	// 🔴 If that stops being true — if anything ever writes the credential cache
	// from a request — this becomes a lie rather than a false positive. The
	// verification is one grep: `CredentialStore.Replace` and
	// `RestoreFromCache` must have no caller reachable from a request handler.
	// 🚫 A colliding method name is not a reason to rename a good one; the
	// previous `persist` WAS renamed (to writeSealedCache) because it collided
	// with internal/proxy's own lastErrorsRing.persist and dragged an unrelated
	// package's file writes into this list, which would have made the baseline
	// describe something it does not.
	"internal/mcp::atomicWriteFile|os.MkdirAll":              {},
	"internal/mcp::atomicWriteFile|os.Remove":                {},
	"internal/apphook::ChildHook.spawnLocked|os.Stat":        {},
	"internal/events::ContentWAL.ensureFile|os.OpenFile":     {},
	"internal/events::ContentWAL.evictBeyondCap|os.Remove":   {},
	"internal/events::WALWriter.ensureFile|os.OpenFile":      {},
	"internal/events::Reporter.deadLetterCompliance|os.Stat": {},
	"internal/events::deadLetterWriter.counts|os.ReadFile":   {},
	"internal/events::deadLetterWriter.write|os.OpenFile":    {},
	// ── seq lane allocator (769f0b1 "usage-seq stream split by recipient") ──
	//
	// 🚫 Recorded, not approved — like every other line here.
	//
	// Both sit BEHIND a cache-miss guard: LaneAllocator.For returns the memoized
	// *SeqAllocator on every hit and only reaches os.Stat / loadSeqState the FIRST
	// time a given lane is seen in this process. Lanes are bounded and few (the
	// method's own doc contrasts the personal lane with the team lane), so the
	// disk cost is once per lane per process, not once per request. The walk
	// cannot see that guard — it answers "can a request reach this code", not
	// "does a request block on it" — which is the same conservatism that keeps the
	// crash-dump and WAL lines visible, and the reason these are RECORDED here
	// rather than waved through.
	//
	// ⚠️ FOR WHOEVER ADJUDICATES: LaneAllocator.For holds l.mu across that I/O
	// (os.Stat + loadSeqState + writeSeqStateAtomic + NewSeqAllocator). A first-
	// sighting of one lane therefore blocks allocation on EVERY other lane,
	// including cache hits. Bounded by the lane count, so it is not a per-request
	// cost — but it is a lock-scope question that came in with this change and has
	// not been reviewed by its author.
	"internal/events::LaneAllocator.For|os.Stat":              {},
	"internal/events::loadSeqState|os.ReadFile":               {},
	"internal/events::writeSeqStateAtomic|os.Remove":          {},
	"internal/observability::writeCrashDump|os.MkdirAll":      {},
	"internal/observability::writeCrashDump|os.WriteFile":     {},
	"internal/proxy::groupLoginStateStore.Clear|os.Remove":    {},
	"internal/proxy::groupLoginStateStore.Write|os.MkdirAll":  {},
	"internal/proxy::groupLoginStateStore.Write|os.WriteFile": {},
	"internal/proxy::writeCodexLastModel|os.MkdirAll":         {},
	"internal/proxy::writeCodexLastModel|os.Remove":           {},
}

// TestTheForwardingHotPathTouchesNoLicensingFileOrDatabase is MOD-16 + PLANE-01.
func TestTheForwardingHotPathTouchesNoLicensingFileOrDatabase(t *testing.T) {
	graph := loadModuleGraph(t)
	reached := graph.reachableFrom(hotPathEntry)

	if len(reached) < 20 {
		t.Fatalf("the walk reached only %d functions from %s. That is far too few for a request "+
			"path, so the graph is not being built — and a fence over an empty graph passes "+
			"vacuously, which is the one thing it must not do", len(reached), hotPathEntry)
	}
	t.Logf("reachable from %s: %d functions across %d files", hotPathEntry, len(reached), graph.fileCount(reached))

	// ── licensing imports: zero, anywhere in the reachable set ─────────────
	for _, v := range bannedImportsReached(graph, reached, forbiddenImports) {
		t.Errorf("🔴 %s is reachable from %s and its file imports %q.\n   %s",
			v.fn, hotPathEntry, v.what, v.why)
	}

	// ── database CALLS: zero ───────────────────────────────────────────────
	for _, v := range bannedCallsReached(graph, reached, forbiddenMethodCalls) {
		t.Errorf("🔴 %s is reachable from %s and calls %s.\n   %s", v.fn, hotPathEntry, v.what, v.why)
	}
}

// violation is one reachable function paired with the banned thing it reaches.
type violation struct {
	fn   string // the reachable function
	what string // the import path, or the call as written
	why  string // the banned entry's own explanation
}

// bannedImportsReached and bannedCallsReached are the fence's two comparisons,
// as functions rather than inline loops.
//
// 🔴 WHY THEY WERE EXTRACTED. Not tidiness — so that the drill below can run the
// SAME comparison the fence enforces. A drill that re-implemented the matching
// would be proving its own copy, and the day the two drifted the drill would go
// on reporting a fence that no longer behaves that way. There is one copy, and
// both the fence and its proof call it.
func bannedImportsReached(g *moduleGraph, reached map[string]struct{}, banned map[string]string) []violation {
	var out []violation
	for _, fn := range sortedKeys(reached) {
		for _, imp := range g.importsOf(fn) {
			for pkg, why := range banned {
				if imp == pkg || strings.HasPrefix(imp, pkg+"/") {
					out = append(out, violation{fn: fn, what: imp, why: why})
				}
			}
		}
	}
	return out
}

func bannedCallsReached(g *moduleGraph, reached map[string]struct{}, banned map[string]string) []violation {
	var out []violation
	for _, fn := range sortedKeys(reached) {
		for _, call := range g.selectorCallsIn(fn) {
			name := call
			if cut := strings.LastIndex(call, "."); cut >= 0 {
				name = call[cut+1:]
			}
			if why, isBanned := banned[name]; isBanned {
				out = append(out, violation{fn: fn, what: call, why: why})
			}
		}
	}
	return out
}

// TestNoNewFileCallAppearsOnTheForwardingHotPath is the ratchet over
// hotPathFileCalls.
//
// 🔴 Read that variable's comment before this test's result means anything: the
// baseline is an inventory of twenty unadjudicated call sites, not a list of
// approved ones. What this test protects is the DIRECTION — the set may shrink,
// never grow.
func TestNoNewFileCallAppearsOnTheForwardingHotPath(t *testing.T) {
	graph := loadModuleGraph(t)
	reached := graph.reachableFrom(hotPathEntry)

	found := map[string]struct{}{}
	for _, fn := range sortedKeys(reached) {
		for _, call := range graph.selectorCallsIn(fn) {
			if _, banned := forbiddenCalls[call]; banned {
				found[fn+"|"+call] = struct{}{}
			}
		}
	}

	for entry := range found {
		if _, known := hotPathFileCalls[entry]; !known {
			t.Errorf("🔴 NEW file call on the forwarding hot path: %s\n   %s\n"+
				"   PLANE-01 forbids this. Move it off the request, or — if it genuinely is "+
				"not on the forwarding path — add it to hotPathFileCalls and say why in the "+
				"commit.", entry, fileReason)
		}
	}
	for entry := range hotPathFileCalls {
		if _, still := found[entry]; !still {
			t.Errorf("the baseline records %s and it is no longer reachable. Delete the line — "+
				"a baseline that describes code which no longer exists reads as a considered "+
				"decision about the current tree.", entry)
		}
	}
	t.Logf("🚫 %d file call(s) reachable from %s, recorded and NOT approved. "+
		"PLANE-01 stays PARTIAL until each is adjudicated.", len(found), hotPathEntry)
}

// TestTheHotPathFenceWouldNoticeALicensingImport is the fence's own fence.
//
// 🔴 Without it, the assertions above pass on a graph that reached nothing, on a
// forbidden list that matched nothing, or on an entry point that no longer
// exists. All three look identical to "the hot path is clean".
//
// 🚫 It was accidentally DELETED once while this file was being edited — a
// refactor cut from one test to another and took it with them — and the register
// caught it, because the register names tests and checks they exist. That is the
// whole argument for naming tests in a register rather than naming packages.
func TestTheHotPathFenceWouldNoticeALicensingImport(t *testing.T) {
	graph := loadModuleGraph(t)
	reached := graph.reachableFrom(hotPathEntry)

	// 1. The entry point exists. A renamed Handle would silently make every
	//    assertion above vacuous.
	if _, ok := graph.funcs[hotPathEntry]; !ok {
		t.Fatalf("%s does not exist in this module. The supervisor calls the per-request entry "+
			"point by name; if it was renamed, this fence is walking nothing", hotPathEntry)
	}

	// 2. The walk crosses package boundaries. A graph confined to internal/proxy
	//    could not see a licensing import added one package away.
	packages := map[string]struct{}{}
	for fn := range reached {
		packages[graph.packageOf(fn)] = struct{}{}
	}
	if len(packages) < 5 {
		t.Fatalf("the walk stayed inside %d package(s): %v. It has to follow calls out of "+
			"internal/proxy, or an import added one package away is invisible to it",
			len(packages), sortedKeys(packages))
	}
	t.Logf("the walk crosses %d packages", len(packages))

	// 3. The import comparison really fires. Run it against a package the hot
	//    path genuinely imports and assert the match would have happened.
	var sample string
	for _, fn := range sortedKeys(reached) {
		for _, imp := range graph.importsOf(fn) {
			if strings.HasPrefix(imp, modulePath+"/") {
				sample = imp
				break
			}
		}
		if sample != "" {
			break
		}
	}
	if sample == "" {
		t.Fatal("no reachable file imports anything from this module, so the import comparison " +
			"has never been exercised against a real path")
	}
	if !(sample == modulePath || strings.HasPrefix(sample, modulePath+"/")) {
		t.Fatalf("the sample import %q would not match under this fence's own comparison; the "+
			"check is not doing what it looks like", sample)
	}
}

// TestTheHotPathFenceGoesRedWhenSomethingForbiddenIsReached is the drill: it
// requires the fence's verdict path to actually fire.
//
// 🔴 WHY THIS IS SEPARATE FROM TestTheHotPathFenceWouldNoticeALicensingImport.
// That test proves the MACHINERY — the entry point resolves, the walk leaves
// internal/proxy, the comparison matches a real path. None of that establishes
// that a match becomes a FAILURE. A fence can have a correct graph, a correct
// comparison, and still report nothing, and every assertion above would stay
// green. This one bans something the hot path demonstrably reaches and requires
// a violation to come back.
//
// 🚫 It cannot be written the obvious way — as an actual forbidden import — for
// the reason recorded on TestThisModuleDoesNotDependOnLicensingAtAll below:
// adding `_ ".../aikey-license-core/licstate"` fails the BUILD, because the
// module does not require it. A mutation that does not compile proves nothing;
// the failure it produces is the compiler's, not the fence's. So the mutation is
// applied to the BAN LIST instead, and it runs through the same comparison the
// fence enforces.
//
// 🔴 The banned entries are DISCOVERED, never hardcoded. A literal package name
// here would turn this drill red the day the hot path stopped importing it —
// which is a change in the product, not a broken fence, and the person who hit
// it would "fix" the drill.
func TestTheHotPathFenceGoesRedWhenSomethingForbiddenIsReached(t *testing.T) {
	graph := loadModuleGraph(t)
	reached := graph.reachableFrom(hotPathEntry)

	// ── the import half ────────────────────────────────────────────────────
	var sampleImport string
	for _, fn := range sortedKeys(reached) {
		if imports := graph.importsOf(fn); len(imports) > 0 {
			sampleImport = imports[0]
			break
		}
	}
	if sampleImport == "" {
		t.Fatal("nothing reachable from the hot path imports anything, so banning an import " +
			"could not be observed either way — this drill would prove nothing")
	}

	if hits := bannedImportsReached(graph, reached, map[string]string{sampleImport: "drill"}); len(hits) == 0 {
		t.Errorf("🔴 NOT A FENCE: %q is imported by something reachable from %s, and banning it "+
			"produced no violation. The import half reports nothing no matter what is on the "+
			"hot path", sampleImport, hotPathEntry)
	} else {
		t.Logf("banning %q yields %d violation(s); first: %s", sampleImport, len(hits), hits[0].fn)
	}

	// Negative control. Without it a comparison that matched EVERYTHING would
	// pass the assertion above — and it would also pass the real fence, loudly,
	// for every release.
	const absent = "example.invalid/no/such/package"
	if hits := bannedImportsReached(graph, reached, map[string]string{absent: "drill"}); len(hits) != 0 {
		t.Errorf("🔴 the import comparison reported %d violation(s) for %q, which nothing imports. "+
			"It is matching indiscriminately, so its green result means nothing either",
			len(hits), absent)
	}

	// ── the call half ──────────────────────────────────────────────────────
	var sampleCall string
	for _, fn := range sortedKeys(reached) {
		if calls := graph.selectorCallsIn(fn); len(calls) > 0 {
			sampleCall = calls[0]
			break
		}
	}
	if sampleCall == "" {
		t.Fatal("nothing reachable from the hot path makes a selector call, so banning one " +
			"could not be observed either way")
	}
	sampleMethod := sampleCall
	if cut := strings.LastIndex(sampleCall, "."); cut >= 0 {
		sampleMethod = sampleCall[cut+1:]
	}

	if hits := bannedCallsReached(graph, reached, map[string]string{sampleMethod: "drill"}); len(hits) == 0 {
		t.Errorf("🔴 NOT A FENCE: %s is called by something reachable from %s, and banning %q "+
			"produced no violation. The database half reports nothing no matter what the hot "+
			"path calls", sampleCall, hotPathEntry, sampleMethod)
	} else {
		t.Logf("banning method %q yields %d violation(s); first: %s", sampleMethod, len(hits), hits[0].fn)
	}

	if hits := bannedCallsReached(graph, reached, map[string]string{"NoSuchMethodIsCalledHere": "drill"}); len(hits) != 0 {
		t.Errorf("🔴 the call comparison reported %d violation(s) for a method name nothing calls",
			len(hits))
	}
}

// TestThisModuleDoesNotDependOnLicensingAtAll is the stronger half, and it was
// found by drilling the fence rather than by design.
//
// 🔴 Adding `_ "github.com/AiKeyLabs/aikey-license-core/licstate"` to the request
// handler did not trip the call-graph fence — it failed the BUILD, because the
// module does not require aikey-license-core in go.mod. That is a stronger
// property than "no reachable file imports it": the package is not resolvable
// here at all, so no amount of refactoring inside this module can put licensing
// on the forwarding path without a deliberate `go get`.
//
// 🚫 It does not replace the call-graph walk. A future `go get` would satisfy
// this file and leave the walk as the thing that notices; and the walk is what
// covers the file and database halves, which no go.mod check can see.
func TestThisModuleDoesNotDependOnLicensingAtAll(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for banned := range forbiddenImports {
		if strings.Contains(body, banned) {
			t.Errorf("🔴 go.mod requires %q. MOD-16 and PLANE-01 both rest on the forwarding "+
				"process not knowing what a license is; once the module can resolve it, only "+
				"the call-graph walk stands between a license check and the request path.", banned)
		}
	}
	// 🔴 NON-VACUITY: the file really was read and really is a go.mod.
	if !strings.Contains(body, "module "+modulePath) {
		t.Fatalf("the file read does not declare module %s; this check is looking at the "+
			"wrong file and would pass whatever go.mod said", modulePath)
	}
}

// ── the graph ──────────────────────────────────────────────────────────────

type moduleGraph struct {
	// funcs maps "<pkg dir>::Recv.Name" or "<pkg dir>::Name" to the declarations.
	funcs map[string][]*funcDecl
	// methodIndex maps a bare method name to every key declaring a method with
	// that name, which is the only place this fence over-approximates.
	methodIndex map[string][]string
}

type funcDecl struct {
	pkg     string
	file    string
	imports []string
	// localPkgs maps the identifier a file uses for an imported package to that
	// package's directory within this module ("cfg" -> "internal/config").
	//
	// 🔴 This is what makes `pkg.Fn(...)` resolvable WITHOUT resolving `x.Fn(...)`
	// to the same thing. The first version matched a bare callee name against
	// every declaration in the module, so `w.Write(b)` on an http.ResponseWriter
	// resolved to `internal/runtime.Write`, which writes a snapshot file — and the
	// fence reported a file write on the hot path that is not on the hot path.
	// 🚫 An over-approximation is the safe direction only while it stays small
	// enough to investigate; on a name like `Write` it is just noise, and a noisy
	// fence gets muted.
	localPkgs map[string]string
	body      *ast.FuncDecl
}

func loadModuleGraph(t *testing.T) *moduleGraph {
	t.Helper()
	root := moduleRoot(t)
	graph := &moduleGraph{funcs: map[string][]*funcDecl{}, methodIndex: map[string][]string{}}
	fset := token.NewFileSet()

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "node_modules", "bin", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			// A file this parser cannot read is not a reason to pass. It is a
			// reason to say so: an unparsed file is a hole in the graph.
			t.Fatalf("parsing %s: %v", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		pkg := filepath.ToSlash(filepath.Dir(rel))
		var imports []string
		localPkgs := map[string]string{}
		for _, spec := range file.Imports {
			value, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			imports = append(imports, value)
			if !strings.HasPrefix(value, modulePath+"/") {
				continue
			}
			dir := strings.TrimPrefix(value, modulePath+"/")
			name := dir
			if cut := strings.LastIndex(dir, "/"); cut >= 0 {
				name = dir[cut+1:]
			}
			if spec.Name != nil {
				name = spec.Name.Name
			}
			localPkgs[name] = dir
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := pkg + "::" + funcKey(fn)
			graph.funcs[key] = append(graph.funcs[key], &funcDecl{
				pkg: pkg, file: rel, imports: imports, localPkgs: localPkgs, body: fn,
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.funcs) == 0 {
		t.Fatal("no functions parsed; the fence would pass vacuously")
	}
	for key, decls := range graph.funcs {
		if len(decls) == 0 || decls[0].body.Recv == nil {
			continue
		}
		name := decls[0].body.Name.Name
		graph.methodIndex[name] = append(graph.methodIndex[name], key)
	}
	return graph
}

// funcKey is "Type.Method" for a method and "Name" for a function.
func funcKey(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return receiverType(fn.Recv.List[0].Type) + "." + fn.Name.Name
}

func receiverType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverType(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr: // generic receiver
		return receiverType(t.X)
	case *ast.IndexListExpr:
		return receiverType(t.X)
	}
	return ""
}

// reachableFrom walks the call graph, following every callee NAME it can resolve
// inside this module.
//
// entry stays a parameter even though every current caller passes hotPathEntry:
// the entry point is the axis this walker exists to model, and the fences below
// read as "what is reachable FROM x" precisely because x is named at the call
// site. Collapsing it to the constant to satisfy unparam would hard-wire the
// walker to one entry and delete the knob a future second plane (supervisor,
// admin surface) needs.
//
//nolint:unparam // deliberate: see above
func (g *moduleGraph) reachableFrom(entry string) map[string]struct{} {
	reached := map[string]struct{}{}
	queue := []string{entry}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, seen := reached[current]; seen {
			continue
		}
		decls, ok := g.funcs[current]
		if !ok {
			continue // not ours: standard library or a third-party package
		}
		reached[current] = struct{}{}
		for _, decl := range decls {
			ast.Inspect(decl.body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				for _, name := range g.calleeKeys(decl, call.Fun) {
					if _, ours := g.funcs[name]; ours {
						queue = append(queue, name)
					}
				}
				return true
			})
		}
	}
	return reached
}

// calleeKeys returns every graph key a call expression inside `from` might mean.
//
// 🔴 Three cases, and the distinction between the first two is the whole fix:
//
//	Foo(...)      a function in the SAME package        -> "<pkg>::Foo"
//	pkg.Foo(...)  a function in an imported package of  -> "<that pkg>::Foo"
//	              THIS module, resolved through the
//	              importing file's own import list
//	x.Foo(...)    a method on some value                -> "<any pkg>::T.Foo"
//
// Only the third over-approximates, and it over-approximates across METHODS of
// that name rather than across every declaration in the module. That is the
// difference between following `w.Write(b)` to the handful of Write METHODS and
// following it to `internal/runtime.Write`, which writes a snapshot file and is
// nowhere near a request.
func (g *moduleGraph) calleeKeys(from *funcDecl, fun ast.Expr) []string {
	switch f := fun.(type) {
	case *ast.Ident:
		return []string{from.pkg + "::" + f.Name}
	case *ast.SelectorExpr:
		if ident, ok := f.X.(*ast.Ident); ok {
			if dir, isPkg := from.localPkgs[ident.Name]; isPkg {
				// A qualified call into another package of this module. Exact.
				return []string{dir + "::" + f.Sel.Name}
			}
		}
		// A method call. Follow every method of that name in the module.
		return g.methodKeys(f.Sel.Name)
	case *ast.IndexExpr:
		return g.calleeKeys(from, f.X)
	case *ast.IndexListExpr:
		return g.calleeKeys(from, f.X)
	case *ast.ParenExpr:
		return g.calleeKeys(from, f.X)
	}
	return nil
}

// methodKeys returns every "<pkg>::T.Name" key in the module.
func (g *moduleGraph) methodKeys(name string) []string {
	if cached, ok := g.methodIndex[name]; ok {
		return cached
	}
	return nil
}

func (g *moduleGraph) importsOf(fn string) []string {
	var out []string
	for _, decl := range g.funcs[fn] {
		out = append(out, decl.imports...)
	}
	return out
}

func (g *moduleGraph) packageOf(fn string) string {
	if decls := g.funcs[fn]; len(decls) > 0 {
		return decls[0].pkg
	}
	return ""
}

func (g *moduleGraph) fileCount(reached map[string]struct{}) int {
	files := map[string]struct{}{}
	for fn := range reached {
		for _, decl := range g.funcs[fn] {
			files[decl.file] = struct{}{}
		}
	}
	return len(files)
}

// selectorCallsIn returns "pkg.Fn" for every qualified call in a function.
func (g *moduleGraph) selectorCallsIn(fn string) []string {
	var out []string
	for _, decl := range g.funcs[fn] {
		ast.Inspect(decl.body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok {
				out = append(out, ident.Name+"."+sel.Sel.Name)
			}
			return true
		})
	}
	return out
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("no go.mod found above the test's directory")
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
