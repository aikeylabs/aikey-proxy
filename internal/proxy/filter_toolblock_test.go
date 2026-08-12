// filter_toolblock_test.go — fences for the 2026-08-10 "方案②" decision:
// agent tool blocks (`tool_result` / `tool_use`) are SCANNED, and every verdict
// they produce is CAPPED to audit (event only; bytes forwarded unchanged).
//
// The decision, the evidence that forced it, and the four costed alternatives
// are in workflow/CI/bugfix/2026-08-10-compliance-tool-result-scan-scope.md.
//
// 🔴 WHAT THESE FENCES EXIST TO STOP: "widen the block types" and "cap the
// action" are one decision, and separating them ships 方案① by accident. The
// built-in credential ruleset is gitleaks-derived — 222 rules, 216 of them
// `block`. Opening tool blocks WITHOUT the cap points those at every file an
// agent reads, so a test fixture with a fake AWS key turns a normal Claude Code
// turn into a hard COMPLIANCE_BLOCKED. TestBlockScanPolicy_ToolBlocksAreAuditOnly
// and TestActionCeiling_ToolBlockVerdictsNeverMaskOrBlock both go RED the moment
// a ceiling is raised, so the accident cannot land quietly.
package proxy

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// toolBlockTypes are the block types opened for AUDIT ONLY. Raising any of them
// to ceilingFull requires the code-corpus holdout + sealed re-run that the
// mask-FP=0 release gate depends on (bugfix §5.3) — this list is the reminder.
var toolBlockTypes = []string{"tool_result", "tool_use"}

// ── the ceiling itself ───────────────────────────────────────────────────────

// TestActionCeiling_ZeroValueIsTheWeakestRung pins the fail-safe direction of
// the type. blockScanPolicy rows and contentPiece literals both rely on it: a
// forgotten `ceiling:` field must yield "audit", never "do whatever the detector
// said".
func TestActionCeiling_ZeroValueIsTheWeakestRung(t *testing.T) {
	var zero actionCeiling
	if zero != ceilingAudit {
		t.Fatalf("actionCeiling zero value must be ceilingAudit (the weakest rung) so an omitted "+
			"field cannot silently widen the blast radius; got %v", zero)
	}
	var piece contentPiece
	if piece.ceiling != ceilingAudit {
		t.Fatal("contentPiece built without an explicit ceiling must default to audit-only")
	}
	if got := ceilingAudit.tighten(ceilingFull); got != ceilingAudit {
		t.Fatalf("tighten must return the STRICTER ceiling; ceilingAudit.tighten(ceilingFull)=%v", got)
	}
	if got := ceilingFull.tighten(ceilingAudit); got != ceilingAudit {
		t.Fatalf("tighten must be symmetric in strictness; ceilingFull.tighten(ceilingAudit)=%v", got)
	}
}

func TestActionCeiling_ClampMatrix(t *testing.T) {
	cases := []struct {
		name      string
		ceiling   actionCeiling
		in        apphook.Action
		want      apphook.Action
		wantCappd bool
	}{
		{"full/mask untouched", ceilingFull, apphook.ActionMask, apphook.ActionMask, false},
		{"full/block untouched", ceilingFull, apphook.ActionBlock, apphook.ActionBlock, false},
		{"full/warn untouched", ceilingFull, apphook.ActionWarn, apphook.ActionWarn, false},
		{"full/allow untouched", ceilingFull, apphook.ActionAllow, apphook.ActionAllow, false},
		{"audit/mask → allow", ceilingAudit, apphook.ActionMask, apphook.ActionAllow, true},
		{"audit/block → allow", ceilingAudit, apphook.ActionBlock, apphook.ActionAllow, true},
		// warn already forwards the bytes unchanged, so capping it further would
		// only throw away signal.
		{"audit/warn kept", ceilingAudit, apphook.ActionWarn, apphook.ActionWarn, false},
		{"audit/allow kept", ceilingAudit, apphook.ActionAllow, apphook.ActionAllow, false},
	}
	for _, c := range cases {
		got, capped := c.ceiling.clamp(c.in)
		if got != c.want || capped != c.wantCappd {
			t.Errorf("%s: clamp(%v)=(%v,%v), want (%v,%v)", c.name, c.in, got, capped, c.want, c.wantCappd)
		}
	}
}

// ── the table ────────────────────────────────────────────────────────────────

// TestBlockScanPolicy_ToolBlocksAreAuditOnly is the "same switch" fence the
// decision asked for: the row that makes a tool block scannable is the same row
// that caps it, so this assertion cannot be satisfied by a half-change.
func TestBlockScanPolicy_ToolBlocksAreAuditOnly(t *testing.T) {
	for _, bt := range toolBlockTypes {
		rule, ok := blockScanPolicy[bt]
		if !ok {
			t.Fatalf("%q is missing from blockScanPolicy — the 2026-08-10 decision (方案②) is that agent "+
				"tool payloads ARE scanned. Removing the row re-opens the silent bypass proven by "+
				"aikey-test/auditeye/tool_result_scope_test.go.", bt)
		}
		if rule.extract == nil {
			t.Fatalf("%q has no extractor — a policy row without one scans nothing", bt)
		}
		if rule.ceiling != ceilingAudit {
			t.Fatalf("🔴 %q is scanned at ceiling %v, expected ceilingAudit.\n\n"+
				"Widening the block types and capping the action are ONE decision (方案②). Raising this "+
				"ceiling points the built-in credential ruleset — 222 rules, 216 of them `block` — at every "+
				"file an agent reads, so a repo's own test fixture can hard-fail the user's turn with "+
				"COMPLIANCE_BLOCKED. That is 方案①, and it is gated on a code-corpus holdout plus a sealed "+
				"re-run of the mask-FP=0 release gate that has NOT been done.\n"+
				"See workflow/CI/bugfix/2026-08-10-compliance-tool-result-scan-scope.md §5.1/§5.3.", bt, rule.ceiling)
		}
	}
}

// TestBlockScanPolicy_ProseBlocksKeepFullCeiling is the other half: capping must
// not leak onto ordinary text, or masking quietly stops working everywhere.
func TestBlockScanPolicy_ProseBlocksKeepFullCeiling(t *testing.T) {
	for _, bt := range []string{"text", "input_text", "output_text"} {
		rule, ok := blockScanPolicy[bt]
		if !ok {
			t.Fatalf("%q must stay scannable — it is the ordinary prose channel", bt)
		}
		if rule.ceiling != ceilingFull {
			t.Fatalf("%q must keep ceilingFull; capping prose disables masking for the main path", bt)
		}
	}
}

// TestBlockScanPolicy_IsTheCompleteSet makes adding a block type a DELIBERATE
// act. A new row changes what crosses to the LLM, so it must not be able to
// arrive as a drive-by edit.
func TestBlockScanPolicy_IsTheCompleteSet(t *testing.T) {
	want := map[string]actionCeiling{
		"text":        ceilingFull,
		"input_text":  ceilingFull,
		"output_text": ceilingFull,
		"tool_result": ceilingAudit,
		"tool_use":    ceilingAudit,
	}
	if len(blockScanPolicy) != len(want) {
		t.Fatalf("blockScanPolicy has %d rows, expected %d — adding or removing a scannable block type is a "+
			"scope decision (spec 2026-06-04 「内容范围」). Update the spec's 关键不变量 line and this fence "+
			"together.", len(blockScanPolicy), len(want))
	}
	for bt, ceiling := range want {
		if blockScanPolicy[bt].ceiling != ceiling {
			t.Errorf("%q: ceiling %v, want %v", bt, blockScanPolicy[bt].ceiling, ceiling)
		}
	}
}

// TestBlockScanPolicy_UnwritablePiecesCannotBeMaskable pins the pairing that
// lets extractToolUseBlock join the whole `input` object into one piece: a piece
// with no write-back target is only sound while its ceiling forbids masking.
// Splitting the join is a prerequisite for ever raising that ceiling.
func TestBlockScanPolicy_UnwritablePiecesCannotBeMaskable(t *testing.T) {
	body := `{"messages":[
		{"role":"user","content":[{"type":"text","text":"plain prose"}]},
		{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash",
			"input":{"command":"echo hi","cwd":"/tmp"}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1",
			"content":[{"type":"text","text":"hi"}]}]}]}`
	pieces, _, ok := extractUserContent([]byte(body), nil)
	if !ok || len(pieces) == 0 {
		t.Fatalf("extractUserContent(ok=%v, pieces=%d)", ok, len(pieces))
	}
	sawUnwritable := false
	for i, p := range pieces {
		if p.setText != nil {
			continue
		}
		sawUnwritable = true
		if p.ceiling == ceilingFull {
			t.Fatalf("piece %d has no write-back target but carries ceilingFull — a Mask verdict on it "+
				"would be silently dropped. Either give it a real setter (split the tool_use.input join "+
				"into per-node pieces) or keep its ceiling below full.", i)
		}
	}
	if !sawUnwritable {
		t.Fatal("expected the joined tool_use.input piece to be unwritable; if the join was split into " +
			"per-node pieces this fence is stale — update it rather than deleting it")
	}
}

// ── extraction behavior ──────────────────────────────────────────────────────

func piecesOf(t *testing.T, body string) []contentPiece {
	t.Helper()
	pieces, _, ok := extractUserContent([]byte(body), nil)
	if !ok {
		t.Fatalf("extractUserContent returned ok=false for %s", body)
	}
	return pieces
}

func findPiece(pieces []contentPiece, needle string) (contentPiece, bool) {
	for _, p := range pieces {
		if strings.Contains(p.text, needle) {
			return p, true
		}
	}
	return contentPiece{}, false
}

// TestCollectContentField_ToolResultTextIsExtractedAtAuditCeiling covers arm B
// of the TOOL-SCOPE case at unit level: Claude Code's Read output shape.
func TestCollectContentField_ToolResultTextIsExtractedAtAuditCeiling(t *testing.T) {
	pieces := piecesOf(t, `{"messages":[{"role":"user","content":[
		{"type":"tool_result","tool_use_id":"t1","content":[
			{"type":"text","text":"SERVICE_TOKEN=abc123"}]}]}]}`)
	p, ok := findPiece(pieces, "SERVICE_TOKEN=abc123")
	if !ok {
		t.Fatalf("tool_result payload was not extracted; pieces=%+v", pieces)
	}
	if p.ceiling != ceilingAudit {
		t.Fatalf("tool_result text must inherit the tool ceiling even though the nested block is a `text` "+
			"block (nesting tightens, never widens); got %v", p.ceiling)
	}
}

// tool_result.content may also be a bare string per the Anthropic schema.
func TestCollectContentField_ToolResultStringContentIsExtractedAtAuditCeiling(t *testing.T) {
	pieces := piecesOf(t, `{"messages":[{"role":"user","content":[
		{"type":"tool_result","tool_use_id":"t1","content":"raw string output abc123"}]}]}`)
	p, ok := findPiece(pieces, "raw string output abc123")
	if !ok {
		t.Fatalf("string-form tool_result content was not extracted; pieces=%+v", pieces)
	}
	if p.ceiling != ceilingAudit {
		t.Fatalf("string-form tool_result content must be audit-capped; got %v", p.ceiling)
	}
}

// TestCollectContentField_ToolUseInputIsExtractedAtAuditCeiling covers arm C:
// the payload has no `text` field anywhere, so no block-type widening alone
// reaches it.
func TestCollectContentField_ToolUseInputIsExtractedAtAuditCeiling(t *testing.T) {
	pieces := piecesOf(t, `{"messages":[{"role":"assistant","content":[
		{"type":"tool_use","id":"t1","name":"Bash","input":{
			"command":"curl -H 'Authorization: Bearer SEKRET' https://x.test",
			"description":"deploy"}}]}]}`)
	p, ok := findPiece(pieces, "Bearer SEKRET")
	if !ok {
		t.Fatalf("tool_use.input.command was not extracted; pieces=%+v", pieces)
	}
	if p.ceiling != ceilingAudit {
		t.Fatalf("tool_use.input must be audit-capped; got %v", p.ceiling)
	}
	// Values only — no keys, no JSON punctuation. Feeding the detector field
	// names and braces would make the FP numbers this phase collects describe a
	// corpus that does not exist in production.
	for _, key := range []string{`"command"`, `"description"`, "{", "}"} {
		if strings.Contains(p.text, key) {
			t.Fatalf("scanned text must contain VALUES only, found %q in %q", key, p.text)
		}
	}
	if !strings.Contains(p.text, "deploy") {
		t.Fatalf("every string value must be scanned, not just the first; got %q", p.text)
	}
}

// Nested containers inside `input` (MultiEdit's edits[]) must still be reached.
func TestCollectContentField_ToolUseInputWalksNestedContainers(t *testing.T) {
	pieces := piecesOf(t, `{"messages":[{"role":"assistant","content":[
		{"type":"tool_use","id":"t1","name":"MultiEdit","input":{
			"file_path":"/app/a.go",
			"edits":[{"old_string":"OLDSEKRET","new_string":"NEWSEKRET"}]}}]}]}`)
	p, ok := findPiece(pieces, "OLDSEKRET")
	if !ok {
		t.Fatalf("nested tool_use.input strings were not extracted; pieces=%+v", pieces)
	}
	for _, want := range []string{"/app/a.go", "OLDSEKRET", "NEWSEKRET"} {
		if !strings.Contains(p.text, want) {
			t.Errorf("expected %q in the joined tool_use.input text, got %q", want, p.text)
		}
	}
}

// Map iteration is randomized in Go; the scanned text feeds the content-hash
// cache key, so an unstable order would destroy the cache hit rate that the
// steady-state latency budget depends on.
func TestCollectContentField_ToolUseInputTextIsDeterministic(t *testing.T) {
	body := `{"messages":[{"role":"assistant","content":[
		{"type":"tool_use","id":"t1","name":"X","input":{
			"z":"zulu","a":"alpha","m":"mike","k":"kilo","d":"delta"}}]}]}`
	first := piecesOf(t, body)[0].text
	for i := 0; i < 50; i++ {
		if got := piecesOf(t, body)[0].text; got != first {
			t.Fatalf("tool_use.input scan text is not deterministic across runs: %q vs %q", first, got)
		}
	}
	if first != "alpha\ndelta\nkilo\nmike\nzulu" {
		t.Fatalf("expected sorted-key value order, got %q", first)
	}
}

// TestCollectContentField_UnknownBlockTypesStillSkipped: opening the tool family
// must not have opened everything. Attachment blocks stay out of scope (spec
// 2026-06-04 「内容范围」), as do reasoning blocks (their signature is verified
// upstream — rewriting them is a hard 400).
func TestCollectContentField_UnknownBlockTypesStillSkipped(t *testing.T) {
	pieces := piecesOf(t, `{"messages":[{"role":"assistant","content":[
		{"type":"thinking","thinking":"THINKINGSECRET","signature":"sig"},
		{"type":"image","source":{"type":"base64","data":"IMAGESECRET"}},
		{"type":"document","source":{"type":"text","data":"DOCSECRET"}},
		{"type":"text","text":"visible"}]}]}`)
	for _, forbidden := range []string{"THINKINGSECRET", "IMAGESECRET", "DOCSECRET"} {
		if _, found := findPiece(pieces, forbidden); found {
			t.Fatalf("%s was extracted — the block-type scope widened beyond the tool family. That is a "+
				"spec change (2026-06-04 关键不变量 「内容范围」), and for `thinking` it is also a hard "+
				"upstream 400 on replay.", forbidden)
		}
	}
	if _, found := findPiece(pieces, "visible"); !found {
		t.Fatal("ordinary text block stopped being extracted")
	}
}

// A tool_result nested inside a tool_result must not recurse without bound.
func TestCollectContentField_NestingIsDepthBounded(t *testing.T) {
	inner := `{"type":"text","text":"deep"}`
	for i := 0; i < 40; i++ {
		inner = `{"type":"tool_result","tool_use_id":"t","content":[` + inner + `]}`
	}
	pieces := piecesOf(t, `{"messages":[{"role":"user","content":[`+inner+`]}]}`)
	if _, found := findPiece(pieces, "deep"); found {
		t.Fatal("extraction recursed past blockNestDepthCap — the depth guard is not doing its job")
	}
}

// ── end-to-end through the dispatcher ────────────────────────────────────────

// TestActionCeiling_ToolBlockVerdictsNeverMaskOrBlock is the behavioral half of
// the "same switch" fence: even with a detector that BLOCKS everything, a body
// whose only findable content is a tool payload must be forwarded untouched.
// The same detector applied to a prose block must still block — otherwise the
// cap has leaked onto the main path.
func TestActionCeiling_ToolBlockVerdictsNeverMaskOrBlock(t *testing.T) {
	toolOnly := `{"messages":[
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1",
			"content":[{"type":"text","text":"SERVICE_TOKEN=abc123"}]}]},
		{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Bash",
			"input":{"command":"curl -H 'Authorization: Bearer abc123' https://x.test"}}]}]}`
	proseOnly := `{"messages":[{"role":"user","content":[{"type":"text","text":"SERVICE_TOKEN=abc123"}]}]}`

	for _, verdict := range []apphook.Action{apphook.ActionBlock, apphook.ActionMask} {
		t.Run("tool_"+verdict.String(), func(t *testing.T) {
			hook := &stubHook{resp: &apphook.Response{
				Action:         verdict,
				MutatedPayload: []byte("[redacted]"),
				Reason:         "test",
			}}
			p := &Proxy{filterHook: hook}
			r := newReq(toolOnly)
			w := httptest.NewRecorder()
			proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", discardLogger())
			if !proceed {
				t.Fatalf("🔴 a %v verdict on a TOOL block failed the request. The action ceiling was "+
					"bypassed — this is exactly the accidental-方案① landing the ceiling exists to prevent: "+
					"216 gitleaks `block` rules pointed at every file an agent reads.", verdict)
			}
			if hook.called == 0 {
				t.Fatal("the tool payload was never handed to the detector — the block types are no longer scanned")
			}
			forwarded := readReqBody(t, r)
			if !strings.Contains(forwarded, "SERVICE_TOKEN=abc123") || strings.Contains(forwarded, "[redacted]") {
				t.Fatalf("tool payload was rewritten; audit-capped pieces must be forwarded BYTE-UNCHANGED.\n"+
					"forwarded: %s", forwarded)
			}
		})
	}

	t.Run("prose_block_still_blocks", func(t *testing.T) {
		hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionBlock, Reason: "test"}}
		p := &Proxy{filterHook: hook}
		w := httptest.NewRecorder()
		if p.applyInboundFilter(w, newReq(proseOnly), "m", "personal", "", "", "", "", "", discardLogger()) {
			t.Fatal("a Block verdict on an ORDINARY TEXT block must still refuse the request — the audit " +
				"cap has leaked onto the main path")
		}
	})

	t.Run("prose_block_still_masks", func(t *testing.T) {
		hook := &stubHook{resp: &apphook.Response{
			Action: apphook.ActionMask, MutatedPayload: []byte("[redacted]")}}
		p := &Proxy{filterHook: hook}
		r := newReq(proseOnly)
		if !p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "", discardLogger()) {
			t.Fatal("mask must not fail the request")
		}
		if forwarded := readReqBody(t, r); !strings.Contains(forwarded, "[redacted]") {
			t.Fatalf("ordinary text block stopped being masked: %s", forwarded)
		}
	})
}

// TestActionCeiling_CappedTeamEventRecordsWhatActuallyHappened: the audit record
// must not claim "mask" when the bytes went out verbatim. A dashboard showing a
// redaction that never happened is the false-safety signal this whole scan-scope
// investigation began with.
func TestActionCeiling_CappedTeamEventRecordsWhatActuallyHappened(t *testing.T) {
	srv, got := complianceSink(t)
	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte("[redacted]"),
		Event:          []byte(`{"event_id":"e1","action_taken":"mask","findings":[]}`),
	}}
	p := &Proxy{filterHook: hook, reporter: teamReporter(t, srv.URL)}
	r := newReq(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1",
		"content":[{"type":"text","text":"SERVICE_TOKEN=abc123"}]}]}]}`)
	if !p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org1", "vk1", "seat1", "sess1", "tr1", discardLogger()) {
		t.Fatal("audit-capped verdict must not fail the request")
	}
	evs := waitEvents(t, got, "capped tool-block finding")
	if len(evs) != 1 {
		t.Fatalf("expected exactly 1 uploaded compliance event (the finding IS recorded — that is the "+
			"whole point of 方案②), got %d", len(evs))
	}
	if a := evs[0]["action_taken"]; a != "audit" {
		t.Fatalf("action_taken=%v, want \"audit\": the proxy did NOT mask, so recording the detector's "+
			"\"mask\" verdict tells the compliance dashboard content was redacted when it crossed the wire "+
			"verbatim", a)
	}
	// Attribution stamping must survive the rewrite.
	for k, want := range map[string]any{"tenant_id": "org1", "virtual_key_id": "vk1", "trace_id": "tr1"} {
		if evs[0][k] != want {
			t.Errorf("%s=%v, want %v — the action rewrite must not drop proxy-stamped attribution", k, evs[0][k], want)
		}
	}
}

// A prose finding's event must keep the detector's own verdict untouched.
func TestActionCeiling_UncappedTeamEventKeepsDetectorVerdict(t *testing.T) {
	srv, got := complianceSink(t)
	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte("[redacted]"),
		Event:          []byte(`{"event_id":"e1","action_taken":"mask"}`),
	}}
	p := &Proxy{filterHook: hook, reporter: teamReporter(t, srv.URL)}
	r := newReq(`{"messages":[{"role":"user","content":[{"type":"text","text":"SERVICE_TOKEN=abc123"}]}]}`)
	if !p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org1", "vk1", "", "", "", discardLogger()) {
		t.Fatal("mask must not fail the request")
	}
	evs := waitEvents(t, got, "uncapped prose finding")
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0]["action_taken"] != "mask" {
		t.Fatalf("action_taken=%v, want \"mask\" — an uncapped verdict must be recorded as the detector "+
			"decided it", evs[0]["action_taken"])
	}
}

// TestActionCeiling_CacheStoresRawVerdictNotCappedOne: the cache is keyed on
// CONTENT, the ceiling is a property of the PIECE. The identical string must
// mask in prose and only audit inside a tool block — which only works if the
// cached verdict is uncapped and the cap is re-applied per piece.
func TestActionCeiling_CacheStoresRawVerdictNotCappedOne(t *testing.T) {
	const secret = "SERVICE_TOKEN=abc123"
	hook := &stubHook{resp: &apphook.Response{
		Action: apphook.ActionMask, MutatedPayload: []byte("[redacted]")}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 50)

	// Tool block first: populates the cache with the RAW mask verdict.
	rTool := newReq(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1",
		"content":[{"type":"text","text":"` + secret + `"}]}]}]}`)
	rTool.Header.Set("X-Claude-Code-Session-Id", "sess-shared")
	p.applyInboundFilter(httptest.NewRecorder(), rTool, "m", "personal", "", "", "",
		resolveSessionID(rTool, "anthropic", "anthropic"), "", discardLogger())
	if got := readReqBody(t, rTool); !strings.Contains(got, secret) {
		t.Fatalf("tool payload must be forwarded unchanged: %s", got)
	}

	// Same session, same string, now in prose: must MASK, replaying the cached
	// verdict rather than inheriting the tool piece's cap.
	rProse := newReq(`{"messages":[{"role":"user","content":[{"type":"text","text":"` + secret + `"}]}]}`)
	rProse.Header.Set("X-Claude-Code-Session-Id", "sess-shared")
	p.applyInboundFilter(httptest.NewRecorder(), rProse, "m", "personal", "", "", "",
		resolveSessionID(rProse, "anthropic", "anthropic"), "", discardLogger())
	if got := readReqBody(t, rProse); !strings.Contains(got, "[redacted]") {
		t.Fatalf("🔴 the cached verdict was stored POST-cap, so a tool-block scan poisoned the prose path "+
			"for the same string. Cache the detector's raw verdict and clamp per piece.\nforwarded: %s", got)
	}
}
