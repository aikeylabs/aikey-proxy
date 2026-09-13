package proxy

// === Fences for design §6 invariants 12 and 13 — the canned-answer red lines ===
//
// bugfix: 需求包 roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// design: §6 不变量 12 (文案不插值) · §6 不变量 13 (转发后不改响应体)
// rules:  R-compliance-canned-answer-3 (代答文案是静态的，不得插值命中片段) · scenario .S1
//         R-compliance-canned-answer-1 (代答短路请求，原文不出上游) — its 射程 note carries
//         invariant 13
// task:   6.4
//
// ⚠️ Deliberately NOT written as `spec:` anchors, following the convention this
// requirement package already set (aikey-control-master
// internal/compliance/grading_document.go): both rules are still PROPOSAL-layer
// — they live in openspec/changes/…, not in openspec/specs/. A `spec:` anchor is
// read by check-spec-writeback as hard evidence the rule has LANDED, and would
// demand it be written back to the steady-state layer, which would assert
// something false: the canned answer is not implemented (see the note below).
// These anchors upgrade to `spec:` in the same change that lands the feature and
// writes the rules back.
//
// ---------------------------------------------------------------------------
// WHAT THE TWO INVARIANTS SAY, IN PLAIN WORDS
//
//	12. The canned answer is printed VERBATIM. Never a template, never a
//	    substitution, never a concatenation of anything the detector found.
//	    If interpolation were allowed, the guardrail would become a channel that
//	    echoes the customer's ID-card number back to whoever sent it — the exact
//	    thing the block was for. 「原文不出信任边界」 with extra steps.
//
//	13. The guardrail writes a response body ONLY while the request has not been
//	    forwarded. Once bytes have gone upstream, the guardrail never rewrites
//	    the reply. There is no "forward first, edit after" middle state.
//	    The placeholder restore is the one documented, pre-existing exception.
//
// ---------------------------------------------------------------------------
// 🔴 WHY THESE ARE SOURCE SCANS AND NOT BEHAVIORAL CASES
//
// Both invariants are NEGATIVE ("never do X"). A behavioral case for a negative
// can only ever prove "the one input I thought of did not trigger X" — it is
// silent about the next code path, and these are precisely the invariants whose
// violation looks like a normal, helpful feature at review time ("let's tell the
// user WHICH field was the problem"). So the assertion is derived from the
// source: enumerate every EXIT the concept has and check each one, rather than
// enumerate the lines somebody happened to touch.
//
// Same shape, and for the same reason, as the sibling fences in
// aikey-control-master: storage/pack_distribution_fence_test.go and
// compliance/rule_route_surface_fence_test.go. Related principle:
// workflow/CI/IDE/claude/principles/documented-contract-needs-enforcement.md.
//
// ---------------------------------------------------------------------------
// ⚠️ WHAT IS AND IS NOT IMPLEMENTED TODAY (2026-09-12, task 6.4) — READ THIS
// BEFORE CONCLUDING ANYTHING FROM A GREEN RUN.
//
// The canned answer is NOT implemented in this repository. `apphook.Action` has
// four values (Allow / Mask / Block / Warn); there is no ActionAnswer, no
// answer-text plumbing and no synthesized 200. `answer` is not yet in the
// database action domain either (that is task 5.1, held by TODO-9).
//
// These fences are therefore written BEFORE the implementation, deliberately.
// They are NOT vacuous while they wait:
//
//   - Invariant 12's fence guards the guardrail short-circuit that DOES exist
//     today — the `case apphook.ActionBlock` branch, which the spec pins as the
//     exact place the canned answer must live ("与 ActionBlock 使用同一短路点与
//     同一 return false 语义", R-compliance-canned-answer-1). One site today;
//     the canned answer will be site two, in scope automatically.
//
//   - Invariant 13's fence guards the response leg, which is fully implemented
//     today and already contains the one legal exception.
//
// Both carry anti-vacuity assertions: if the scan ever finds nothing, it fails
// instead of passing, because a scan that matches nothing passes forever.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The guardrail's own sources.
//
// "The guardrail" means the compliance filter: the thing that reads a detector
// verdict and acts on it. Not the whole proxy — the proxy legitimately rewrites
// response bodies for reasons that have nothing to do with compliance (an
// upstream 400 relabel, error forensics, SSE draining), and invariant 13 does
// not speak about those.
//
// Hand-listed, but NOT hand-trusted: TestFence_GuardrailFileListIsComplete
// derives the real set from "which files consume an apphook verdict constant"
// and fails if this list has drifted. A canned answer written in a brand-new
// canned_answer.go therefore cannot slip past by not being listed.
var guardrailFiles = map[string]string{
	"filter_dispatch.go": "applyInboundFilter — the verdict switch and the short-circuit " +
		"(case apphook.ActionBlock → writeJSONError → return false). The canned answer lands here.",
	"filter_content.go":     "content extraction and per-piece ceilings — produces the pieces a verdict applies to",
	"filter_cache.go":       "verdict cache — replays a previous verdict, so it can reach the same short-circuit",
	"filter_performance.go": "the 15ms budget and fail-open bookkeeping around the detect call",
	"filter_restore.go": "the placeholder restore — the ONE documented response-leg exception to invariant 13 " +
		"(non-streaming half)",
	"sse_restore.go": "the streaming half of that same exception (newSSEPlaceholderRestorer)",
}

// ---------------------------------------------------------------------------
// Fence 0 — the file list above must still describe reality.
//
// WHY THIS EXISTS: both fences below derive their scope from `guardrailFiles`.
// A list is the weakest part of any derived scan — the failure mode is not a red
// test, it is a green one that stopped looking. If someone implements the canned
// answer in canned_answer.go and does not list it, fence 12 would scan the old
// files, find the old single site, pass, and guard nothing.
//
// The independent signal used here is "which non-test file references an
// apphook verdict constant" — a file that decides what to do with a detector
// verdict IS the guardrail, whatever it is called.
func TestFence_GuardrailFileListIsComplete(t *testing.T) {
	files := parseGuardrailPackage(t)

	var unlisted []string
	for name, f := range files {
		if guardrailFiles[name] != "" {
			continue
		}
		if pos := f.firstVerdictConstantRef(); pos != "" {
			unlisted = append(unlisted, fmt.Sprintf("%s (first reference at %s)", name, pos))
		}
	}
	sort.Strings(unlisted)
	if len(unlisted) > 0 {
		t.Errorf(`these files consume an apphook verdict constant but are not in guardrailFiles:
  %s

A file that decides what to do with a detector verdict is part of the compliance
guardrail, and the two fences below derive their scope from that list. Leaving a
file out does not make them fail — it makes them scan somewhere else and pass.

Fix: add the file to guardrailFiles with one line saying what it does.`,
			strings.Join(unlisted, "\n  "))
	}

	// Staleness in the other direction: an entry naming a file that no longer
	// exists would quietly shrink the scope of both fences.
	for name := range guardrailFiles {
		if _, ok := files[name]; !ok {
			t.Errorf("guardrailFiles[%q] names a file that does not exist in this package. "+
				"Remove it in the same change that removed the file — a stale entry hides how "+
				"much the fences below stopped looking at.", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Fence 12 — the guardrail short-circuit body is verbatim.
// ---------------------------------------------------------------------------

// guardrailVerbatimSources names the non-literal expressions that are allowed to
// reach the client through a guardrail short-circuit, WITH THE REASON.
//
// 🚫 Adding an entry is a deliberate, reviewable act, and it is the only way to
// widen this fence. The default for a new expression is "the build asks you".
//
// 🔴 An interpolation primitive can NEVER be exempted here — that check runs
// before this table is consulted (see interpolationPrimitives). An entry that
// tries to whitelist Sprintf does nothing.
var guardrailVerbatimSources = map[string]string{
	// The detector's human-readable reason, reached as `msg := resp.Reason` in
	// applyInboundFilter's COMPLIANCE_BLOCKED refusal (the other assignment to
	// msg is the constant fallback "request blocked by compliance policy", which
	// needs no exemption).
	//
	// resp.Reason is content-free BY CONSTRUCTION on this path, and the reason is
	// worth writing down because it is not obvious from here: apphook's
	// ChildHook.Detect only ever sets Reason on the degraded/error paths, and
	// every one of those returns ActionAllow (internal/apphook/childhook.go —
	// the `res := &Response{...}` built from a successful roundtrip never
	// populates Reason at all). A Block verdict therefore always arrives with
	// Reason == "" and the client gets the constant.
	//
	// ⚠️ BOUNDARY OF THIS FENCE, stated out loud: that guarantee lives in the
	// DETECTOR's wire, in another repository. A source scan of aikey-proxy cannot
	// see a future detector version that starts stuffing the matched text into
	// Reason. If Reason ever becomes free-form detector output, this entry is
	// wrong and the fix is to stop passing it to the client, not to relax the
	// fence.
	"resp.Reason": "the detector's human-readable reason, which apphook never populates on a " +
		"Block verdict (see the note above), so the client always gets the constant fallback",
}

// interpolationPrimitives are the calls that turn "print this text" into "print
// this text with something substituted into it". Invariant 12 forbids ALL of
// them on the short-circuit path, not merely the ones that happen to be fed
// detector output today: the canned answer has nothing to substitute, so any
// substitution machinery on this path is a defect regardless of its arguments.
//
// Keyed by the dotted call spelling; matched on suffix so a renamed import alias
// (fmtpkg.Sprintf) does not slip through.
var interpolationPrimitives = []string{
	"fmt.Sprintf", "fmt.Sprint", "fmt.Sprintln", "fmt.Errorf", "fmt.Fprintf", "fmt.Fprint",
	"strings.Replace", "strings.ReplaceAll", "strings.NewReplacer",
	"bytes.Replace", "bytes.ReplaceAll",
	"regexp.ReplaceAll", "regexp.ReplaceAllString", "regexp.ReplaceAllLiteralString",
	"os.Expand", "os.ExpandEnv",
	"template.Must", "template.New", "template.HTMLEscapeString",
	".Execute", ".ExecuteTemplate", ".Replace", ".Expand",
}

// TestFence_GuardrailShortCircuitBodyIsNeverInterpolated pins design §6 invariant
// 12 / R-compliance-canned-answer-3.
//
// WHAT IT DERIVES: every call inside a guardrail file that writes to the
// enclosing function's http.ResponseWriter — i.e. every place the guardrail
// hands bytes to the client INSTEAD of forwarding. Today that is exactly one:
// the COMPLIANCE_BLOCKED refusal in applyInboundFilter. The canned answer is
// specified to short-circuit at that same point, so it will be site two without
// anyone updating this test.
//
// WHAT IT ASSERTS about each site: every argument is VERBATIM-SAFE — a literal,
// a constant from an imported package, a package-level constant of this package,
// a local whose every assignment is itself verbatim-safe, or an expression named
// in guardrailVerbatimSources with a reason. And, separately and
// unconditionally, no argument may contain an interpolation primitive.
//
// WHY THE CHECK IS ON THE ARGUMENTS AND NOT INSIDE writeJSONError: the framing
// the writer applies afterwards (the "AiKey: " prefix, JSON encoding) is not
// interpolation of content and is fenced elsewhere. Invariant 12 is about what
// the guardrail HANDS OVER. Checking the callee's body instead would redden on
// aikeyErrorEnvelope's constant prefix — a false positive that would get the
// fence weakened within a week.
//
// Mutation check (both run and recorded in task-execution/runs/task-6.4-report.md):
// replace the final argument with fmt.Sprintf("%s", head) and this goes red
// naming filter_dispatch.go and the line.
func TestFence_GuardrailShortCircuitBodyIsNeverInterpolated(t *testing.T) {
	files := parseGuardrailPackage(t)

	var sites []clientWriteSite
	for name, f := range files {
		if guardrailFiles[name] == "" {
			continue
		}
		sites = append(sites, f.clientWriteSites()...)
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].pos < sites[j].pos })

	// Anti-vacuity. The guardrail has had a client-facing short-circuit since the
	// compliance filter existed; finding none means the derivation broke (the
	// ResponseWriter got wrapped in a struct, the short-circuit moved to a file
	// missing from guardrailFiles, the AST shape changed). A scan that matches
	// nothing passes forever.
	if len(sites) == 0 {
		t.Fatalf(`no guardrail short-circuit write site found — this fence is looking at nothing.

It derives sites by finding calls whose first argument is (or whose receiver is)
the enclosing function's http.ResponseWriter, inside the files listed in
guardrailFiles. At least one has existed continuously: the COMPLIANCE_BLOCKED
refusal in applyInboundFilter.

Fix the derivation in the same change that moved the code. Do not delete this
assertion — it is the only thing standing between this fence and a permanent
green that guards nothing.`)
	}

	used := map[string]bool{}
	for _, s := range sites {
		t.Logf("short-circuit site: %s → %s(%s)", s.pos, s.callee, strings.Join(s.argSrc, ", "))
		for i, arg := range s.args {
			if i == s.writerArg {
				continue // the ResponseWriter itself
			}
			// Collect which exemptions this argument's assignment graph relies on
			// FIRST, unconditionally. Doing it only on the success path made the
			// staleness guard fire as collateral whenever an argument was
			// rejected for an unrelated reason — two errors for one defect, and
			// the second one told the reader to delete a live exemption.
			safe, why, sources := localIsVerbatimSafe(s.argSrc[i], s)
			for _, src := range sources {
				used[src] = true
			}

			if prim := findInterpolation(arg); prim != "" {
				t.Errorf(`%s: argument %d of %s calls %s.

design §6 invariant 12 / R-compliance-canned-answer-3: the text a guardrail
short-circuit hands the client is printed VERBATIM. There is nothing to
substitute — the canned answer is administrator-authored text stored in
compliance_rules.answer_text / compliance_grading.ladder[level].answer_text, and
it goes out byte for byte, `+"`{{IDCARD_1}}`"+` included.

The moment substitution is possible here, the guardrail becomes a channel that
echoes what the detector found back to whoever sent it — the customer's ID-card
number, returned by the very response that was supposed to withhold it. That is
the same red line as 「原文不出客户信任边界」, reached from the other side.

This one has no exemption. guardrailVerbatimSources cannot whitelist it.
Fix: pass the stored text through unmodified.`,
					s.pos, i, s.callee, prim)
				continue
			}
			expr := s.argSrc[i]
			if verbatimSafe(arg, s.file) {
				continue
			}
			// A local whose every in-function assignment is verbatim-safe is safe.
			// Consulted BEFORE the exemption table on purpose: following the
			// assignments makes the table say what is actually risky (resp.Reason)
			// instead of the variable that happens to hold it (msg). A table keyed
			// on local names would be re-approved for free by any rename.
			if safe {
				if len(sources) > 0 {
					t.Logf("  arg %d %q proven verbatim by following its assignments; "+
						"listed source(s): %v", i, expr, sources)
				}
				continue
			}
			if reason, ok := guardrailVerbatimSources[expr]; ok {
				used[expr] = true
				t.Logf("  arg %d %q allowed by guardrailVerbatimSources: %s", i, expr, reason)
				continue
			}
			if why != "" {
				t.Errorf(`%s: argument %d of %s is %q, and %s

design §6 invariant 12 / R-compliance-canned-answer-3: the body of a guardrail
short-circuit must be administrator-authored text or a compile-time constant —
never a value derived from the content that was just scanned.

Fix: hand over the stored text (or a constant). If this expression really is
verbatim administrator text, add it to guardrailVerbatimSources WITH THE REASON
— say why it cannot carry detector output, the way the existing entry does.`,
					s.pos, i, s.callee, expr, why)
				continue
			}
			t.Errorf(`%s: argument %d of %s is %q, which this fence cannot prove is verbatim.

design §6 invariant 12 / R-compliance-canned-answer-3: only literals, constants,
and administrator-authored text may reach the client through a guardrail
short-circuit.

Fix: pass a constant or the stored answer text. If this expression is verbatim by
construction, add it to guardrailVerbatimSources WITH THE REASON.`,
				s.pos, i, s.callee, expr)
		}
	}

	// Keep the escape hatch honest. An exemption for an expression nobody passes
	// any more would silently pre-authorize the name if it ever came back.
	for expr := range guardrailVerbatimSources {
		// "Used" covers the normal case; the wider scan covers the case where the
		// argument was rejected for some OTHER reason, which must not also be
		// reported as a stale exemption — one defect, one error message.
		if used[expr] || expressionAppearsInAnySite(sites, expr) {
			continue
		}
		t.Errorf("guardrailVerbatimSources[%q] is stale: no guardrail short-circuit passes that "+
			"expression any more. Remove it in the same change that removed the call — an "+
			"exemption outliving its call site is a pre-approval for whoever reuses the name.", expr)
	}
}

// ---------------------------------------------------------------------------
// Fence 13 — nothing the guardrail owns may rewrite a forwarded response.
// ---------------------------------------------------------------------------

// responseLegGuardrailExemptions names the guardrail identifiers that ARE
// allowed on the response leg, with the reason. Today it holds exactly the
// placeholder restore — design §6 invariant 13 calls it out by name as the one
// pre-existing exception.
//
// 🚫 An entry here says: "this piece of the compliance guardrail runs AFTER the
// request went upstream, and that is intended." That is a design decision about
// the trust boundary, not a routing detail. There is exactly one today and the
// bar for a second is a user sign-off, because a second one means invariant 13
// has stopped being an invariant.
var responseLegGuardrailExemptions = map[string]string{
	"maskRestoreFromContext": "reads the request leg's placeholder→original map off the request " +
		"context. Reads only; writes nothing to the body.",
	"restoreMaskedResponseBody": "the documented exception (design §6 invariant 13, 「占位符还原是既有" +
		"且唯一的例外」): swaps {{PHONE_1}} back to the number the USER themselves sent, in the reply " +
		"to that same user. It restores what the guardrail removed on the way out — it does not " +
		"introduce anything the client did not already have. Non-streaming half.",
	"newSSEPlaceholderRestorer": "the streaming half of the same exception. Wrapped OUTSIDE the " +
		"drainer so token extraction and the audit observer keep seeing the MASKED text; the " +
		"restored originals reach the client only.",
}

// TestFence_GuardrailNeverRewritesAForwardedResponse pins design §6 invariant 13.
//
// WHAT IT DERIVES: every function or closure that assigns to a
// *http.Response.Body — i.e. every place in this package that rewrites what the
// client will read AFTER the request has gone upstream. Then, for each, which
// identifiers declared by the compliance guardrail it references.
//
// WHAT IT ASSERTS: that set is exactly the placeholder restore.
//
// WHY THIS SHAPE AND NOT "assert the canned answer is not called from
// ModifyResponse": the invariant is not about the canned answer. It is that the
// guardrail has ONE response-leg member, forever. A test naming today's mistake
// says nothing about the next one — and the next one is easy to write and looks
// reasonable: ModifyResponse already has the verdict on the context, so
// "forward, then swap the body for the canned answer if it was blocked" is a
// three-line change that no behavioral test would notice, and it would send the
// prompt upstream first. The whole point of a canned answer is that the content
// never left.
//
// Mutation check (run and recorded in task-execution/runs/task-6.4-report.md):
// add a body-composing helper to filter_dispatch.go and call it from serveRoute's
// ModifyResponse closure — this goes red naming forward_and_resolve.go and the line.
func TestFence_GuardrailNeverRewritesAForwardedResponse(t *testing.T) {
	files := parseGuardrailPackage(t)

	// The guardrail's surface: every package-level name its own files declare.
	surface := map[string]string{}
	for name, f := range files {
		if guardrailFiles[name] == "" {
			continue
		}
		for _, decl := range f.packageLevelNames() {
			surface[decl] = name
		}
	}
	if len(surface) == 0 {
		t.Fatal("the compliance guardrail declares no package-level names — the scan is not " +
			"looking at the package it thinks it is")
	}
	t.Logf("guardrail surface: %d package-level names across %d files", len(surface), len(guardrailFiles))

	var units []responseLegUnit
	for _, f := range files {
		units = append(units, f.responseLegUnits()...)
	}
	sort.Slice(units, func(i, j int) bool { return units[i].pos < units[j].pos })

	// Anti-vacuity: the proxy has rewritten response bodies since it existed
	// (error forensics, upstream 400 relabel, the restore itself). Zero means the
	// derivation broke, not that the invariant got safer.
	if len(units) == 0 {
		t.Fatalf(`no *http.Response.Body assignment found in this package — this fence is looking at nothing.

It derives its scope from "who assigns to a *http.Response's Body", which is the
literal act invariant 13 governs. Several such sites have existed continuously.
If the response leg was restructured, fix the derivation in the same change.`)
	}

	used := map[string]bool{}
	for _, u := range units {
		var offenders []string
		// One line per offending NAME, not per occurrence: a name used ten times
		// is one defect, and ten identical lines bury the other nine names.
		reported := map[string]bool{}
		for _, ref := range u.refs {
			src, isGuardrail := surface[ref.name]
			if !isGuardrail {
				continue
			}
			if _, ok := responseLegGuardrailExemptions[ref.name]; ok {
				used[ref.name] = true
				continue
			}
			if reported[ref.name] {
				continue
			}
			reported[ref.name] = true
			offenders = append(offenders, fmt.Sprintf("%s (declared in %s) at %s", ref.name, src, ref.pos))
		}
		sort.Strings(offenders)
		if len(offenders) > 0 {
			t.Errorf(`%s rewrites a forwarded response body AND reaches into the compliance guardrail:
  %s

design §6 invariant 13: 护栏只在「请求未发往上游」时写响应体；一旦转发过上游，
响应体永不由护栏改写（占位符还原是既有且唯一的例外）。

This code runs on the RESPONSE leg — the request has already been sent to the
LLM. A guardrail that edits the reply here has already lost: the content it was
protecting left the trust boundary one hop ago. There is no "forward, then fix
it up" state; the guardrail either short-circuits before forwarding
(applyInboundFilter returning false) or it keeps its hands off.

For the canned answer specifically this is the difference between the feature and
its opposite: R-compliance-canned-answer-1 exists because the request is never
issued. Synthesizing the answer after forwarding produces the same bytes for the
client and sends the customer's prompt upstream anyway.

Fix: move the decision to applyInboundFilter, before the forward.
If this really must run on the response leg, that reverses a red line — take it
to the user, then add it to responseLegGuardrailExemptions with who signed off.`,
				u.name, strings.Join(offenders, "\n  "))
		}
	}

	// Staleness: an exemption for a name the response leg no longer calls would
	// pre-authorize it for whoever reuses the name later.
	for name := range responseLegGuardrailExemptions {
		if !used[name] {
			t.Errorf("responseLegGuardrailExemptions[%q] is stale: no response-leg body write "+
				"references it any more. Remove it in the same change that removed the call — "+
				"the exception list is the record of how many times invariant 13 has been "+
				"broken on purpose, and it must stay countable.", name)
		}
	}
}

// ===========================================================================
// source-scanning internals
// ===========================================================================

type identRef struct{ name, pos string }

type clientWriteSite struct {
	pos       string
	callee    string
	args      []ast.Expr
	argSrc    []string
	writerArg int // index of the ResponseWriter argument, or -1 for a method call on it
	file      *guardFile
	fn        *ast.FuncDecl
}

type responseLegUnit struct {
	name string
	pos  string
	refs []identRef
}

type guardFile struct {
	name    string
	path    string
	syntax  *ast.File
	fset    *token.FileSet
	imports map[string]bool
}

// parseGuardrailPackage parses the non-test sources of this package once.
//
// Test files are excluded on purpose: this fence lives in one, and a fence that
// scanned its own error strings would find "fmt.Sprintf" in its own explanation
// of why fmt.Sprintf is forbidden.
func parseGuardrailPackage(t *testing.T) map[string]*guardFile {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package source: %v", err)
	}
	out := map[string]*guardFile{}
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			imports := map[string]bool{}
			for _, imp := range file.Imports {
				name := ""
				if imp.Name != nil {
					name = imp.Name.Name
				} else if p, err := strconv.Unquote(imp.Path.Value); err == nil {
					name = p[strings.LastIndex(p, "/")+1:]
				}
				if name != "" && name != "_" && name != "." {
					imports[name] = true
				}
			}
			base := filepath.Base(path)
			out[base] = &guardFile{name: base, path: path, syntax: file, fset: fset, imports: imports}
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed zero non-test files — the fence is not in the package it thinks it is")
	}
	return out
}

// firstVerdictConstantRef reports where this file first mentions an apphook
// verdict constant, or "".
func (f *guardFile) firstVerdictConstantRef() string {
	verdicts := map[string]bool{
		"ActionAllow": true, "ActionMask": true, "ActionBlock": true,
		"ActionWarn": true, "ActionAnswer": true,
	}
	found := ""
	ast.Inspect(f.syntax, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || !verdicts[sel.Sel.Name] {
			return true
		}
		if base, ok := sel.X.(*ast.Ident); ok && base.Name == "apphook" {
			found = f.fset.Position(sel.Pos()).String()
			return false
		}
		return true
	})
	return found
}

// packageLevelNames returns every name this file declares at package level.
func (f *guardFile) packageLevelNames() []string {
	var out []string
	for _, decl := range f.syntax.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil { // methods are reached through a receiver, not by bare name
				out = append(out, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch sp := s.(type) {
				case *ast.TypeSpec:
					out = append(out, sp.Name.Name)
				case *ast.ValueSpec:
					for _, n := range sp.Names {
						out = append(out, n.Name)
					}
				}
			}
		}
	}
	return out
}

// clientWriteSites finds every call in this file whose first argument is, or
// whose receiver is, the enclosing function's http.ResponseWriter.
//
// That shape IS the concept "hand bytes to the client instead of forwarding":
// writeJSONError(w, …), w.Write(…), json.NewEncoder(w) all match, and so will a
// future writeCannedAnswer(w, …). Detecting the ResponseWriter rather than a
// list of writer function names is what makes the derivation survive someone
// adding a new writer.
func (f *guardFile) clientWriteSites() []clientWriteSite {
	var out []clientWriteSite
	for _, decl := range f.syntax.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		writers := map[string]bool{}
		for _, p := range fn.Type.Params.List {
			if isResponseWriter(p.Type) {
				for _, n := range p.Names {
					writers[n.Name] = true
				}
			}
		}
		if len(writers) == 0 {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			writerArg := -1
			if len(call.Args) > 0 {
				if id, ok := call.Args[0].(*ast.Ident); ok && writers[id.Name] {
					writerArg = 0
				}
			}
			if writerArg == -1 {
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok || !writers[id.Name] {
					return true
				}
			}
			site := clientWriteSite{
				pos:       f.fset.Position(call.Pos()).String(),
				callee:    exprString(call.Fun),
				args:      call.Args,
				writerArg: writerArg,
				file:      f,
				fn:        fn,
			}
			for _, a := range call.Args {
				site.argSrc = append(site.argSrc, exprString(a))
			}
			out = append(out, site)
			return true
		})
	}
	return out
}

// responseLegUnits finds every function or closure in this file that assigns to
// a *http.Response's Body, and records the bare identifiers it references.
//
// A closure is its own unit: serveRoute's ModifyResponse literal is where the
// response leg actually lives, and attributing its references to the whole
// 600-line serveRoute would make one exemption cover everything inside it.
func (f *guardFile) responseLegUnits() []responseLegUnit {
	var out []responseLegUnit
	for _, decl := range f.syntax.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		f.collectResponseLegUnits(fn.Name.Name, fn.Recv, fn.Type, fn.Body, map[string]bool{}, &out)
	}
	return out
}

func (f *guardFile) collectResponseLegUnits(name string, recv *ast.FieldList, typ *ast.FuncType,
	body *ast.BlockStmt, inherited map[string]bool, out *[]responseLegUnit) {

	responses := map[string]bool{}
	for k := range inherited {
		responses[k] = true
	}
	collectResponseParams(recv, responses)
	collectResponseParams(typ.Params, responses)

	assigns := false
	var refs []identRef
	inspectOwnScope(body, func(n ast.Node) {
		switch v := n.(type) {
		case *ast.FuncLit:
			f.collectResponseLegUnits(
				fmt.Sprintf("%s/closure@%s", name, f.fset.Position(v.Pos())),
				nil, v.Type, v.Body, responses, out)
		case *ast.AssignStmt:
			for _, lhs := range v.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Body" {
					continue
				}
				if base, ok := sel.X.(*ast.Ident); ok && responses[base.Name] {
					assigns = true
				}
			}
		case *ast.SelectorExpr:
			// A selector's .Sel is a method or field name, never a package-level
			// reference. Counting it produced false hits on Close/Get, which are
			// method names that collide with guardrail helper names.
			if base, ok := v.X.(*ast.Ident); ok {
				refs = append(refs, identRef{base.Name, f.fset.Position(base.Pos()).String()})
			}
		case *ast.Ident:
			refs = append(refs, identRef{v.Name, f.fset.Position(v.Pos()).String()})
		}
	})
	if !assigns {
		return
	}
	*out = append(*out, responseLegUnit{
		name: fmt.Sprintf("%s (%s)", name, f.name),
		pos:  f.fset.Position(body.Pos()).String(),
		refs: refs,
	})
}

// inspectOwnScope walks root, visiting every node EXCEPT:
//
//   - the bodies of nested function literals (the literal itself is visited so
//     the caller can turn it into its own unit, but its contents are not
//     attributed to the enclosing function);
//   - the .Sel half of a selector expression, which is a method or field name
//     rather than a package-level reference. Counting it produced false hits on
//     Close and Get — method names on unrelated types that happen to collide
//     with guardrail helper names.
func inspectOwnScope(root ast.Node, visit func(ast.Node)) {
	var walk func(ast.Node)
	walk = func(n ast.Node) {
		if n == nil {
			return
		}
		if fl, ok := n.(*ast.FuncLit); ok && ast.Node(fl) != root {
			visit(fl) // the caller recurses into it as a separate unit
			return
		}
		if sel, ok := n.(*ast.SelectorExpr); ok {
			visit(sel)
			walk(sel.X)
			return
		}
		visit(n)
		var kids []ast.Node
		ast.Inspect(n, func(c ast.Node) bool {
			if c == nil || c == n {
				return c == n
			}
			kids = append(kids, c)
			return false // collect direct children only
		})
		for _, k := range kids {
			walk(k)
		}
	}
	walk(root)
}

func collectResponseParams(fl *ast.FieldList, into map[string]bool) {
	if fl == nil {
		return
	}
	for _, f := range fl.List {
		st, ok := f.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if isPkgType(st.X, "http", "Response") {
			for _, n := range f.Names {
				into[n.Name] = true
			}
		}
	}
}

func isResponseWriter(e ast.Expr) bool { return isPkgType(e, "http", "ResponseWriter") }

func isPkgType(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	base, ok := sel.X.(*ast.Ident)
	return ok && base.Name == pkg && sel.Sel.Name == name
}

// findInterpolation reports the first interpolation primitive called anywhere
// inside expr, or "".
func findInterpolation(expr ast.Expr) string {
	found := ""
	ast.Inspect(expr, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := exprString(call.Fun)
		for _, prim := range interpolationPrimitives {
			if name == prim || strings.HasSuffix(name, prim) {
				found = name
				return false
			}
		}
		return true
	})
	return found
}

// verbatimSafe reports whether expr can be proven to carry no request content:
// a literal, a selector on an imported package (http.StatusForbidden), or a
// concatenation of such things.
func verbatimSafe(expr ast.Expr, f *guardFile) bool {
	switch v := expr.(type) {
	case *ast.BasicLit:
		return true
	case *ast.SelectorExpr:
		base, ok := v.X.(*ast.Ident)
		// An imported package's exported identifier is a compile-time constant or
		// a function of the standard library; it cannot be this request's content.
		// A selector on a LOCAL variable (resp.Reason) is a different animal and
		// deliberately falls through to the exemption table.
		return ok && f.imports[base.Name]
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return false
		}
		return verbatimSafe(v.X, f) && verbatimSafe(v.Y, f)
	case *ast.ParenExpr:
		return verbatimSafe(v.X, f)
	}
	return false
}

// localIsVerbatimSafe follows a local identifier's assignments within the
// enclosing function. It returns (true, "", used) when every assignment is
// verbatim-safe, and (false, why, used) when one is not. `used` names the
// guardrailVerbatimSources entries the proof relied on, so the staleness guard
// can tell a live exemption from a forgotten one.
func localIsVerbatimSafe(name string, s clientWriteSite) (bool, string, []string) {
	var problems, used []string
	seen := 0
	record := func(rhs ast.Expr) {
		seen++
		if prim := findInterpolation(rhs); prim != "" {
			problems = append(problems, fmt.Sprintf("assigned %s at %s, which calls %s",
				exprString(rhs), s.file.fset.Position(rhs.Pos()), prim))
			return
		}
		if verbatimSafe(rhs, s.file) {
			return
		}
		if _, ok := guardrailVerbatimSources[exprString(rhs)]; ok {
			used = append(used, exprString(rhs))
			return
		}
		problems = append(problems, fmt.Sprintf("assigned %s at %s, which is not a literal, a "+
			"constant, or a listed verbatim source", exprString(rhs), s.file.fset.Position(rhs.Pos())))
	}
	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range v.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name != name || i >= len(v.Rhs) {
					continue
				}
				record(v.Rhs[i])
			}
		case *ast.ValueSpec:
			for i, n := range v.Names {
				if n.Name != name || i >= len(v.Values) {
					continue
				}
				record(v.Values[i])
			}
		}
		return true
	})
	if seen == 0 {
		return false, "", nil // not a local of this function — caller reports the generic message
	}
	if len(problems) > 0 {
		return false, strings.Join(problems, "; "), used
	}
	return true, "", used
}

// expressionAppearsInAnySite reports whether expr is still written anywhere in
// a function that holds a guardrail short-circuit. Used only by the staleness
// guard: an exemption is stale when the expression is GONE, not when the one
// argument that used to carry it was rejected for an unrelated reason.
func expressionAppearsInAnySite(sites []clientWriteSite, expr string) bool {
	seen := map[*ast.FuncDecl]bool{}
	for _, s := range sites {
		if seen[s.fn] {
			continue
		}
		seen[s.fn] = true
		found := false
		ast.Inspect(s.fn.Body, func(n ast.Node) bool {
			if found || n == nil {
				return false
			}
			if e, ok := n.(ast.Expr); ok && exprString(e) == expr {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.BasicLit:
		return v.Value
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		var args []string
		for _, a := range v.Args {
			args = append(args, exprString(a))
		}
		return exprString(v.Fun) + "(" + strings.Join(args, ", ") + ")"
	case *ast.BinaryExpr:
		return exprString(v.X) + " " + v.Op.String() + " " + exprString(v.Y)
	case *ast.ParenExpr:
		return "(" + exprString(v.X) + ")"
	case *ast.StarExpr:
		return "*" + exprString(v.X)
	case *ast.UnaryExpr:
		return v.Op.String() + exprString(v.X)
	case *ast.IndexExpr:
		return exprString(v.X) + "[" + exprString(v.Index) + "]"
	case *ast.CompositeLit:
		return exprString(v.Type) + "{…}"
	case *ast.ArrayType:
		return "[]" + exprString(v.Elt)
	case *ast.FuncLit:
		return "func(…){…}"
	}
	return fmt.Sprintf("%T", e)
}
