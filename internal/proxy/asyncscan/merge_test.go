package asyncscan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/pkg/deepscan"
)

func ruleFinding(start, end int, entity string) deepscan.Finding {
	return deepscan.Finding{
		Engine: deepscan.EngineRules, RuleID: "secret.connection-uri-password",
		Category: "secret", EntityType: entity, Severity: "high", Confidence: 95,
		Start: start, End: end, Detector: "regex",
	}
}

// job is a 64 KiB piece whose first 16 KiB the fast layer already inspected.
func job() PieceJob {
	const headBytes, total = 16 * 1024, 64 * 1024
	return PieceJob{
		JobID: "j1", TenantID: "org_a", AuditUnitID: "au_1", ContentSHA256: "sha",
		Source: deepscan.SourceRequest, Text: strings.Repeat("a", total), HeadBytes: headBytes,
		Engines: []string{deepscan.EngineRules},
	}
}

// TestAsyncRules_TailFindingAbsoluteOffset: a finding in the tail keeps its
// ABSOLUTE offset into the piece.
//
// The receiver scans chunks, so the naive result is chunk-relative. If a
// chunk-relative offset reached the audit row, a reviewer opening the finding
// would be shown the wrong span of the prompt — confidently and silently.
func TestAsyncRules_TailFindingAbsoluteOffset(t *testing.T) {
	j := job()
	m := Merge(j, deepscan.ResultFrame{
		JobID: "j1", Status: deepscan.StatusComplete,
		ScannedBytes: 64 * 1024, TotalBytes: 64 * 1024,
		Findings: []deepscan.Finding{ruleFinding(50_000, 50_060, "CREDENTIAL_DSN")},
	}, apphook.ActionBlock, apphook.ActionBlock)

	if len(m.Findings) != 1 {
		t.Fatalf("the tail finding was lost: %+v", m.Findings)
	}
	if m.Findings[0].Start != 50_000 || m.Findings[0].End != 50_060 {
		t.Errorf("offsets moved: got [%d,%d), want [50000,50060)", m.Findings[0].Start, m.Findings[0].End)
	}
}

// TestAsyncRules_HeadAlreadyScannedNotDuplicated: findings that end at or before
// head_bytes were already reported by the synchronous layer and must be dropped.
//
// Without this the same credential is filed twice per turn — once by the fast
// layer, once by the async lane — under two different event ids, so neither
// database constraint can collapse them.
func TestAsyncRules_HeadAlreadyScannedNotDuplicated(t *testing.T) {
	j := job()
	m := Merge(j, deepscan.ResultFrame{
		JobID: "j1", Status: deepscan.StatusComplete,
		Findings: []deepscan.Finding{
			ruleFinding(100, 160, "CREDENTIAL_DSN"),                   // fully inside the head
			ruleFinding(16*1024-60, 16*1024, "CN_PHONE"),              // ends exactly AT head_bytes
			ruleFinding(16*1024-10, 16*1024+50, "CREDENTIAL_API_KEY"), // STRADDLES the boundary
			ruleFinding(40_000, 40_060, "CREDENTIAL_DSN"),             // tail — new coverage
		},
	}, apphook.ActionBlock, apphook.ActionBlock)

	kept := map[string]bool{}
	for _, f := range m.Findings {
		kept[f.EntityType] = true
	}
	if kept["CN_PHONE"] {
		t.Error("a finding ending exactly at head_bytes was kept; the fast layer already reported it")
	}
	if len(m.Findings) != 2 {
		t.Fatalf("want 2 kept (the straddler and the tail), got %d: %+v", len(m.Findings), m.Findings)
	}
	if !kept["CREDENTIAL_API_KEY"] {
		t.Error("a finding STRADDLING head_bytes was dropped — the fast layer only saw its first half, " +
			"so nobody reported the whole entity. This is the case the 2048-byte chunk overlap exists for.")
	}
	if !kept["CREDENTIAL_DSN"] {
		t.Error("the tail finding was dropped")
	}
}

// TestAsyncRules_PlainTextBlockRuleIsLeak: ordinary user text carries a rule
// whose action is block. The synchronous layer never saw those bytes, so the
// content WENT UPSTREAM. That is the high-risk case an admin must be shown.
func TestAsyncRules_PlainTextBlockRuleIsLeak(t *testing.T) {
	j := job()
	m := Merge(j, deepscan.ResultFrame{
		JobID: "j1", Status: deepscan.StatusComplete,
		Findings:     []deepscan.Finding{ruleFinding(40_000, 40_060, "CREDENTIAL_DSN")},
		RuleVerdicts: []deepscan.RangeVerdict{{Start: 32768, End: 49152, Action: "block"}},
	}, apphook.ActionBlock /* plain text: full enforcement */, apphook.ActionBlock)

	if !m.WouldHaveBlocked {
		t.Fatal("a block-action rule in UNSCANNED plain text is a leak: those bytes reached the model")
	}
	if m.Scenario != ScenarioAsyncRuleLeak {
		t.Errorf("scenario = %q, want %q", m.Scenario, ScenarioAsyncRuleLeak)
	}
	if m.ActionTaken != "audit" {
		t.Errorf("action_taken = %q, want \"audit\" — nothing WAS done, and the record must say so", m.ActionTaken)
	}
}

// TestAsyncRules_ToolResultCappedNotLeak: the same block rule inside a tool
// result is NOT a leak.
//
// 🔴 The distinction is the whole point of the ceiling ladder. A tool_result
// block is pinned to the audit ceiling (2026-08-10 方案②), so even if the
// synchronous layer HAD seen those bytes it would have recorded and forwarded
// them. Nothing was lost by scanning late. Calling it a leak would fill the
// admin's high-risk queue with cases where the product behaved exactly as
// designed — and a queue full of non-incidents is a queue nobody reads.
func TestAsyncRules_ToolResultCappedNotLeak(t *testing.T) {
	j := job()
	m := Merge(j, deepscan.ResultFrame{
		JobID: "j1", Status: deepscan.StatusComplete,
		Findings:     []deepscan.Finding{ruleFinding(40_000, 40_060, "CREDENTIAL_DSN")},
		RuleVerdicts: []deepscan.RangeVerdict{{Start: 32768, End: 49152, Action: "block"}},
	}, apphook.ActionWarn /* tool_result: audit ceiling */, apphook.ActionBlock)

	if m.WouldHaveBlocked {
		t.Fatal("a capped tool_result block was reported as a leak; the sync layer would not have blocked it either")
	}
	if m.Scenario != ScenarioAsyncRuleAudit {
		t.Errorf("scenario = %q, want %q", m.Scenario, ScenarioAsyncRuleAudit)
	}
	if len(m.Findings) != 1 {
		t.Error("the finding itself must still be recorded — not a leak is not the same as not worth knowing")
	}
}

// TestAsyncRules_DeploymentCeilingWarnNotLeak: the ORG turned enforcement down
// to warn (filter_max_action). Then no content would ever have been blocked, so
// nothing the async lane finds can be a leak.
func TestAsyncRules_DeploymentCeilingWarnNotLeak(t *testing.T) {
	j := job()
	m := Merge(j, deepscan.ResultFrame{
		JobID: "j1", Status: deepscan.StatusComplete,
		Findings:     []deepscan.Finding{ruleFinding(40_000, 40_060, "CREDENTIAL_DSN")},
		RuleVerdicts: []deepscan.RangeVerdict{{Start: 32768, End: 49152, Action: "block"}},
	}, apphook.ActionBlock, apphook.ActionWarn /* org-wide ceiling */)

	if m.WouldHaveBlocked {
		t.Fatal("a leak was reported on a deployment whose ceiling forbids blocking — nothing would have been blocked")
	}
	if m.Scenario != ScenarioAsyncRuleAudit {
		t.Errorf("scenario = %q, want %q", m.Scenario, ScenarioAsyncRuleAudit)
	}
}

// TestAsyncScanResult_VersionSkewCounted: a node that answered with a different
// ruleset than this proxy runs is COUNTED, and its result is still used.
//
// Discarding it would mean a fleet mid-upgrade produces no coverage at all;
// accepting it silently would mean an admin cannot explain why one machine
// reports findings another does not. So: use it, and make the skew visible.
func TestAsyncScanResult_VersionSkewCounted(t *testing.T) {
	j := job()
	j.DetectorVersion, j.ContentVersion = "abc123", "cv-7"

	same := Merge(j, deepscan.ResultFrame{
		JobID: "j1", Status: deepscan.StatusComplete,
		Engines:  deepscan.EngineResults{Rules: deepscan.EngineResult{DetectorVersion: "abc123", ContentVersion: "cv-7"}},
		Findings: []deepscan.Finding{ruleFinding(40_000, 40_060, "CREDENTIAL_DSN")},
	}, apphook.ActionBlock, apphook.ActionBlock)
	if same.VersionSkew {
		t.Error("identical versions reported skew")
	}

	for name, eng := range map[string]deepscan.EngineResult{
		"detector differs": {DetectorVersion: "def456", ContentVersion: "cv-7"},
		"ruleset differs":  {DetectorVersion: "abc123", ContentVersion: "cv-9"},
	} {
		m := Merge(j, deepscan.ResultFrame{
			JobID: "j1", Status: deepscan.StatusComplete, Engines: deepscan.EngineResults{Rules: eng},
			Findings: []deepscan.Finding{ruleFinding(40_000, 40_060, "CREDENTIAL_DSN")},
		}, apphook.ActionBlock, apphook.ActionBlock)
		if !m.VersionSkew {
			t.Errorf("%s: skew not detected (%+v)", name, eng)
		}
		if len(m.Findings) != 1 {
			t.Errorf("%s: the result was DISCARDED on skew; a fleet mid-upgrade would then produce no coverage", name)
		}
	}
}

// TestAsyncScanEvents_CarryProxyStampedIdentityAndNoContent checks what actually
// reaches master.
func TestAsyncScanEvents_CarryProxyStampedIdentityAndNoContent(t *testing.T) {
	j := job()
	m := Merge(j, deepscan.ResultFrame{
		JobID: "j1", Status: deepscan.StatusPartial, Reason: deepscan.ReasonPieceCap,
		ScannedBytes: 60 * 1024, TotalBytes: 64 * 1024,
		Findings:     []deepscan.Finding{ruleFinding(40_000, 40_060, "CREDENTIAL_DSN")},
		RuleVerdicts: []deepscan.RangeVerdict{{Start: 32768, End: 49152, Action: "block"}},
	}, apphook.ActionBlock, apphook.ActionBlock)

	id := RequestIdentity{
		TenantID: "org_a", SeatID: "seat-7", VirtualKeyID: "vk-3",
		SessionID: "sess-9", TraceID: "trace-42",
	}
	events := BuildEvents(m, id)
	if len(events) != 1 {
		t.Fatalf("want one rule event, got %d", len(events))
	}
	b, err := json.Marshal(events[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(b, &got)

	for k, want := range map[string]string{
		"tenant_id": "org_a", "seat_id": "seat-7", "virtual_key_id": "vk-3",
		"session_id": "sess-9", "trace_id": "trace-42",
		"scenario": ScenarioAsyncRuleLeak, "action_taken": "audit",
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %q — the proxy is the ONLY party that knows this, and it must stamp it", k, got[k], want)
		}
	}
	if got["event_id"] != RuleScanEventID("au_1") {
		t.Errorf("event_id = %v, want the content-derived %s", got["event_id"], RuleScanEventID("au_1"))
	}
	// 🚫 No content, ever: the piece text, the matched substring, a snippet.
	for _, banned := range []string{"context_snippet", "redacted_snippet", "prompt", "evidence"} {
		if _, present := got[banned]; present {
			t.Errorf("the async event carries %q; remote results never include content and must not gain it here", banned)
		}
	}
	if strings.Contains(string(b), strings.Repeat("a", 64)) {
		t.Error("the event body contains a run of the piece text")
	}
	// Coverage travels so master can tell "clean" from "we ran out of budget".
	cov, ok := got["scan_coverage"].(map[string]any)
	if !ok {
		t.Fatalf("no scan_coverage on a partial result: %s", b)
	}
	if cov["status"] != deepscan.StatusPartial {
		t.Errorf("scan_coverage.status = %v, want partial", cov["status"])
	}
}

// TestWouldHaveBlocked_CannedAnswerIsARefusal — a tail finding inside a range the
// receiver judged `answer` (代答) is a leak exactly like one judged `block`: the
// synchronous layer would have refused the request either way.
func TestWouldHaveBlocked_CannedAnswerIsARefusal(t *testing.T) {
	m := Merge(job(), deepscan.ResultFrame{
		JobID: "j1", Status: deepscan.StatusComplete,
		Findings:     []deepscan.Finding{ruleFinding(50_000, 50_060, "CN_ID_CARD")},
		RuleVerdicts: []deepscan.RangeVerdict{{Start: 49_000, End: 51_000, Action: apphook.ActionAnswer.String()}},
	}, apphook.ActionBlock, apphook.ActionBlock)
	if !m.WouldHaveBlocked || m.Scenario != ScenarioAsyncRuleLeak {
		t.Fatalf("a tail hit under a canned-answer rule was not reported as a leak (would_have_blocked=%v scenario=%q)", m.WouldHaveBlocked, m.Scenario)
	}
}
