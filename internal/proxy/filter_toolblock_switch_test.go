// filter_toolblock_switch_test.go — fences for the operator switch that turns
// agent tool-block scanning off (用户 2026-08-10, following the CN_ADDRESS lane
// switch paradigm: the on/off state is a RUNG on the existing policy row, not a
// second config surface).
//
// 🔴 WHAT THESE FENCES EXIST TO STOP — three distinct regressions:
//
//  1. "off" degenerating into "scan but don't cap". The switch must remove the
//     policy row from effect entirely; if it only relaxed the ceiling it would do
//     the exact opposite of what an operator asked for. The rung and the ceiling
//     are the SAME field precisely so this cannot be expressed.
//  2. "on" quietly losing the cap. 方案② is only acceptable because every tool
//     verdict is capped to audit; adding a switch must not become the edit that
//     separates "widen the block types" from "cap the action".
//  3. "off" re-opening the response-side restore channel. restoreSkipBlockTypes
//     is DERIVED from the policy table (filter_restore.go): if the switch worked
//     by deleting the rows, tool blocks would drop out of the skip set and
//     restore would start writing plaintext originals into tool_use arguments —
//     the S3 echo chain, re-opened by a scan-scope setting. The switch therefore
//     moves the row to ceilingOff and the CANONICAL table (which restore reads)
//     never changes at all.
package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// withToolBlockScan sets the rung for one test and restores the previous one.
// The effective table is process-global (see the note on
// activeBlockScanPolicyPtr), so these tests must not run in parallel.
func withToolBlockScan(t *testing.T, mode string) {
	t.Helper()
	prev := ToolBlockScanMode()
	applied, ok := SetToolBlockScanMode(mode)
	if !ok {
		t.Fatalf("SetToolBlockScanMode(%q) rejected the rung (applied=%q)", mode, applied)
	}
	t.Cleanup(func() { SetToolBlockScanMode(prev) })
}

// agentToolTurn is a body whose ONLY scannable payload is tool traffic: a
// tool_result carrying file output and a tool_use carrying a command line.
const agentToolTurn = `{"messages":[{"role":"user","content":[
	{"type":"tool_result","tool_use_id":"t1","content":[
		{"type":"text","text":"SERVICE_TOKEN=abc123"}]},
	{"type":"tool_use","name":"Bash","input":{"command":"curl -H 'x: sk-live-9999'"}}]}]}`

// ── the switch removes the row, it does not relax it ─────────────────────────

// TestToolBlockSwitch_OffExtractsNothingFromToolBlocks is the primary fence:
// with the switch off the extractor must behave exactly as it did before 方案②
// — tool payloads are not extracted, so nothing about them ever reaches the
// detector, and no compliance event can be produced for them.
func TestToolBlockSwitch_OffExtractsNothingFromToolBlocks(t *testing.T) {
	withToolBlockScan(t, string(toolBlockScanOff))

	pieces, _, ok := extractUserContent([]byte(agentToolTurn), nil)
	if ok && len(pieces) > 0 {
		for _, p := range pieces {
			t.Errorf("🔴 switch is OFF but a tool payload was still extracted: %q (ceiling=%v).\n"+
				"OFF must mean the policy row does not apply at all — not a relaxed ceiling. "+
				"Anything extracted here is sent to the detector and recorded.", p.text, p.ceiling)
		}
	}
	// The pre-2026-08-10 contract for a tool-only turn: nothing scannable, so the
	// dispatcher takes its "no filterable content" branch.
	if ok && len(pieces) == 0 {
		t.Log("tool-only turn yielded zero pieces (before the audit-only design) — correct")
	}
}

// TestToolBlockSwitch_OffLeavesProseUntouched — the switch is scoped to tool
// traffic. If it also silenced ordinary prose it would disable masking on the
// main path, which is a far worse outcome than the latency it was meant to save.
func TestToolBlockSwitch_OffLeavesProseUntouched(t *testing.T) {
	withToolBlockScan(t, string(toolBlockScanOff))

	pieces := piecesOf(t, `{"messages":[{"role":"user","content":[
		{"type":"text","text":"my token is sk-live-1234"},
		{"type":"tool_result","tool_use_id":"t1","content":[
			{"type":"text","text":"SERVICE_TOKEN=abc123"}]}]}]}`)

	prose, found := findPiece(pieces, "my token is")
	if !found {
		t.Fatal("🔴 prose disappeared with the tool switch off — the switch must not touch text blocks")
	}
	if prose.ceiling != ceilingFull {
		t.Fatalf("prose ceiling %v, want ceilingFull; capping prose disables masking on the main path", prose.ceiling)
	}
	if _, leaked := findPiece(pieces, "SERVICE_TOKEN"); leaked {
		t.Error("🔴 tool_result nested text was still extracted with the switch off — " +
			"nesting must inherit the OFF rung (tighten takes the strictest)")
	}
}

// TestToolBlockSwitch_OnStillEnforcesTheCeiling is the other direction: the
// switch must not become the place where the audit cap gets lost.
func TestToolBlockSwitch_OnStillEnforcesTheCeiling(t *testing.T) {
	withToolBlockScan(t, string(toolBlockScanAudit))

	pieces := piecesOf(t, agentToolTurn)
	for _, needle := range []string{"SERVICE_TOKEN=abc123", "curl -H"} {
		p, found := findPiece(pieces, needle)
		if !found {
			t.Fatalf("switch is ON but %q was not extracted — the row must be in effect", needle)
		}
		if p.ceiling != ceilingAudit {
			t.Fatalf("🔴 %q extracted at ceiling %v, want ceilingAudit.\n"+
				"Turning the row ON must hand it the audit cap in the SAME step. A tool payload at "+
				"ceilingFull points 216 gitleaks `block` rules at every file an agent reads (方案①), "+
				"which is gated on a code-corpus holdout that has not been run.", needle, p.ceiling)
		}
	}
}

// TestToolBlockSwitch_RungAndCeilingAreOneField pins the structural property the
// 2026-08-10 decision depends on: there is no way to name a rung without also
// naming the action ceiling its rows run at, and only "off" maps to "not in
// effect". A future "mask" rung must come through here too.
func TestToolBlockSwitch_RungAndCeilingAreOneField(t *testing.T) {
	want := map[toolBlockScanMode]actionCeiling{
		toolBlockScanOff:   ceilingOff,
		toolBlockScanAudit: ceilingAudit,
	}
	for mode, ceiling := range want {
		if got := toolBlockCeilingFor(mode); got != ceiling {
			t.Errorf("toolBlockCeilingFor(%q)=%v, want %v", mode, got, ceiling)
		}
	}
	// Every rung the switch accepts must be in the table above — a rung added
	// without a ceiling mapping is exactly the half-change 方案② forbids.
	for _, raw := range []string{"off", "audit"} {
		if _, ok := want[toolBlockScanMode(raw)]; !ok {
			t.Errorf("rung %q is accepted by SetToolBlockScanMode but has no declared ceiling", raw)
		}
	}
	// And the ONLY rung that switches the row off is "off": a ceiling that is
	// merely weaker must still scan.
	if toolBlockCeilingFor(toolBlockScanAudit) == ceilingOff {
		t.Fatal("🔴 the audit rung resolved to ceilingOff — 'on' would silently scan nothing")
	}
}

// ── failure directions ───────────────────────────────────────────────────────

// TestToolBlockSwitch_UnknownAndEmptyDegradeToDefault — a typo must never turn
// scanning off (nor on). Same asymmetry as the detector's AddressLaneAction:
// absent/invalid degrades to the safe default rung, never to `off`.
func TestToolBlockSwitch_UnknownAndEmptyDegradeToDefault(t *testing.T) {
	t.Cleanup(func() { SetToolBlockScanMode(string(defaultToolBlockScanMode)) })

	applied, ok := SetToolBlockScanMode("offf")
	if ok {
		t.Error("a misspelled rung must be reported as rejected so the supervisor can WARN")
	}
	if applied != string(defaultToolBlockScanMode) {
		t.Errorf("misspelled rung applied %q, want the default %q — a typo must not disable scanning",
			applied, defaultToolBlockScanMode)
	}
	if ToolBlockScanMode() != string(defaultToolBlockScanMode) {
		t.Errorf("live table after a typo is %q, want %q", ToolBlockScanMode(), defaultToolBlockScanMode)
	}

	applied, ok = SetToolBlockScanMode("")
	if !ok {
		t.Error("unset is not an operator error — it must apply the default without a WARN")
	}
	if applied != string(defaultToolBlockScanMode) {
		t.Errorf("unset applied %q, want %q", applied, defaultToolBlockScanMode)
	}
}

// TestToolBlockSwitch_DefaultIsOn pins the shipped default. Flipping it to off
// would silently restore the audit blind spot arms B/C of the TOOL-SCOPE case
// proved, on every install, with no log line saying so.
func TestToolBlockSwitch_DefaultIsOn(t *testing.T) {
	if defaultToolBlockScanMode != toolBlockScanAudit {
		t.Fatalf("default rung is %q, want %q", defaultToolBlockScanMode, toolBlockScanAudit)
	}
	if toolBlockCeilingFor(defaultToolBlockScanMode) != ceilingAudit {
		t.Fatal("the default rung must run the rows at the audit cap")
	}
}

// TestToolBlockSwitch_OffDoesNotReopenRestore is fence (3) from the header, and
// the least obvious one. restoreSkipBlockTypes is derived from the policy table;
// turning the scan off must not hand the response leg permission to write
// plaintext originals back into tool blocks.
func TestToolBlockSwitch_OffDoesNotReopenRestore(t *testing.T) {
	withToolBlockScan(t, string(toolBlockScanOff))

	for _, bt := range toolBlockTypes {
		if !restoreSkipBlockTypes()[bt] {
			t.Errorf("🔴 %q dropped out of the restore skip set when scanning was switched off.\n"+
				"Restore would then write originals into a channel the request leg cannot mask — the S3 "+
				"echo chain, re-opened by a SCAN-SCOPE setting. The switch must move the row to "+
				"ceilingOff, never delete it from the canonical table.", bt)
		}
		// The canonical table is what restore reads; it must be untouched.
		if rule, ok := blockScanPolicy[bt]; !ok || rule.ceiling != ceilingAudit {
			t.Errorf("🔴 canonical blockScanPolicy[%q] changed with the switch (present=%v ceiling=%v) — "+
				"only the EFFECTIVE table may move", bt, ok, rule.ceiling)
		}
	}
}

// ── the ladder itself ────────────────────────────────────────────────────────

// TestActionCeiling_OffIsRankedStrictestButIsNotTheZeroValue pins both halves of
// the ceilingOff design: it must be the strictest rung for tighten(), and it must
// NOT be what an author gets by forgetting the field.
func TestActionCeiling_OffIsRankedStrictestButIsNotTheZeroValue(t *testing.T) {
	var zero actionCeiling
	if zero == ceilingOff {
		t.Fatal("🔴 ceilingOff must not be the zero value — a forgotten `ceiling:` field would then " +
			"silently stop scanning a block type, which is the leak direction")
	}
	if ceilingOff.rank() >= ceilingAudit.rank() || ceilingAudit.rank() >= ceilingFull.rank() {
		t.Fatalf("rank order must be off < audit < full; got off=%d audit=%d full=%d",
			ceilingOff.rank(), ceilingAudit.rank(), ceilingFull.rank())
	}
	for _, other := range []actionCeiling{ceilingAudit, ceilingFull, ceilingOff} {
		if got := ceilingOff.tighten(other); got != ceilingOff {
			t.Errorf("ceilingOff.tighten(%v)=%v, want ceilingOff — a disabled parent must disable "+
				"everything nested under it", other, got)
		}
		if got := other.tighten(ceilingOff); got != ceilingOff {
			t.Errorf("%v.tighten(ceilingOff)=%v, want ceilingOff", other, got)
		}
	}
	if ceilingOff.String() != "off" {
		t.Errorf("ceilingOff renders as %q; logs and audit records must use the ladder vocabulary",
			ceilingOff.String())
	}
}

// ── the rung is externally readable ──────────────────────────────────────────

// TestToolBlockSwitch_RungIsOnTheDiagnosticsSurface — a rung that only appears
// in a startup log line is not an externally readable health signal, and a
// silently-off scan lane makes every downstream audit assertion vacuously green.
func TestToolBlockSwitch_RungIsOnTheDiagnosticsSurface(t *testing.T) {
	p := &Proxy{}
	for _, mode := range []string{string(toolBlockScanOff), string(toolBlockScanAudit)} {
		func() {
			withToolBlockScan(t, mode)
			w := httptest.NewRecorder()
			p.handleDiagnosticsPipeline(w, httptest.NewRequest("GET", "/v1/diagnostics/pipeline", nil))
			if w.Code != 200 {
				t.Fatalf("diagnostics returned %d", w.Code)
			}
			var got PipelineDiagnostics
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode diagnostics: %v\n%s", err, w.Body.String())
			}
			if got.MaskRestore.ToolBlockScan != mode {
				t.Errorf("diagnostics reports tool_block_scan=%q while the live table is %q — the "+
					"health signal must be derived from what is actually running",
					got.MaskRestore.ToolBlockScan, mode)
			}
			if !strings.Contains(w.Body.String(), `"tool_block_scan"`) {
				t.Error("tool_block_scan is missing from the diagnostics payload")
			}
		}()
	}
}
