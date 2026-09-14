package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// These fences all guard ONE property: the asynchronous scan lane produces no
// user-visible effect when it works, so its ONLY operator surface is this health
// block. 健康信号必须可被外部读取 — a lane whose failures live in a log file has
// no health signal at all, and "the dashboard looked fine" is exactly how a
// silently-dark compliance lane survives to production.
//
// Mount point corrected 2026-09-11 (baseline-forensics §F6): the design said
// `GET /admin/apps/health`, which in this codebase is the app-pipeline
// last-call cache (app_slug / status_code / error_type — no compliance entry and
// no sub-sections). The real compliance surface is this one.

// TestPipelineHealth_DeepScanRemoteSection: with nodes configured, the section
// names them, carries a breaker state per node, and reports the counters an
// operator needs to tell "nothing to scan" from "nothing got through".
func TestPipelineHealth_DeepScanRemoteSection(t *testing.T) {
	h := DeepScanHealth{
		Mode:   "remote",
		Reason: "ok",
		Status: "ok",
		Nodes:  []DeepScanNodeHealth{{ID: "scan-1", Breaker: "closed"}},
		DeepScanCounters: DeepScanCounters{
			EnqueuedTotal: 12, ForwardedTotal: 10, FailedTotal: 2,
			DroppedTotal: 1, DroppedBytesTotal: 4096, TruncatedTotal: 1, QueueLen: 3,
		},
		Skipped:                  DeepScanSkipped{NoNodes: 1, Scanned: 7, Blocked: 2},
		CoverageUnsupportedTotal: 4,
		Rules: &AsyncRulesHealth{
			CompletedTotal: 5, PartialTotal: 1, HighRiskTotal: 1,
			DroppedTotal: 0, VersionSkewTotal: 2, Executor: "idle",
		},
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Field names are a contract: the E2E suite and the ops SOP read them by name.
	for _, k := range []string{
		"mode", "reason", "status", "nodes",
		"enqueued_total", "dropped_total", "dropped_bytes_total", "forwarded_total",
		"failed_total", "truncated_total", "queue_len", "skipped_total",
		"coverage_unsupported_total", "rules",
	} {
		if _, ok := got[k]; !ok {
			t.Errorf("health section is missing %q; JSON was %s", k, b)
		}
	}
	skipped, _ := got["skipped_total"].(map[string]any)
	for _, k := range []string{"no_nodes", "scanned", "blocked"} {
		if _, ok := skipped[k]; !ok {
			t.Errorf("skipped_total is missing %q — an operator cannot tell WHY work was skipped", k)
		}
	}
	rules, _ := got["rules"].(map[string]any)
	for _, k := range []string{"completed_total", "partial_total", "high_risk_total", "dropped_total", "version_skew_total", "executor"} {
		if _, ok := rules[k]; !ok {
			t.Errorf("rules section is missing %q", k)
		}
	}
	// 🚫 No content, ever. This block is read by dashboards and pasted into
	// tickets; one prompt fragment here is a disclosure with a very long tail.
	for _, banned := range []string{"prompt", "content", "text", "snippet", "evidence"} {
		if strings.Contains(strings.ToLower(string(b)), `"`+banned+`"`) {
			t.Errorf("the health section carries a %q field — it must never carry content", banned)
		}
	}
}

// TestPipelineHealth_DeepScanLocalSection: on a box with no on-machine daemon,
// the bge counters are ABSENT, not zero.
//
// 🔴 This is the whole point of the test. A zero says "we looked and found
// nothing"; an absent field says "this engine is not running here". Reporting 0
// for an engine that never ran is the reassuring-direction failure this project
// keeps getting bitten by — the dashboard is green and the lane is dark.
func TestPipelineHealth_DeepScanLocalSection(t *testing.T) {
	h := DeepScanHealth{
		Mode: "local", Reason: "local_daemon_absent", Status: "ok",
		DeepScanCounters: DeepScanCounters{EnqueuedTotal: 3, ForwardedTotal: 3},
		Rules:            &AsyncRulesHealth{CompletedTotal: 3, Executor: "running"},
		// BGE intentionally nil: no daemon on this machine.
	}
	b, _ := json.Marshal(h)
	var got map[string]any
	_ = json.Unmarshal(b, &got)

	if got["reason"] != "local_daemon_absent" {
		t.Errorf("reason = %v, want local_daemon_absent", got["reason"])
	}
	if _, present := got["bge"]; present {
		t.Errorf("bge counters are present with no daemon installed; they must be ABSENT, not 0 — JSON was %s", b)
	}
	if _, present := got["rules"]; !present {
		t.Error("the rule lane DOES run locally, so its counters must be present")
	}
	if got["mode"] != "local" {
		t.Errorf("mode = %v, want local", got["mode"])
	}
}

// TestPipelineHealth_AsyncRulesSection: the rule back-scan counters distinguish
// completed from partial from dropped, and surface version skew between what a
// node ran and what this proxy runs.
func TestPipelineHealth_AsyncRulesSection(t *testing.T) {
	h := DeepScanHealth{Mode: "remote", Reason: "ok", Status: "ok",
		Rules: &AsyncRulesHealth{
			CompletedTotal: 40, PartialTotal: 3, HighRiskTotal: 2,
			DroppedTotal: 1, VersionSkewTotal: 5, Executor: "absent",
		}}
	b, _ := json.Marshal(h)
	var got struct {
		Rules AsyncRulesHealth `json:"rules"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Rules.PartialTotal != 3 {
		t.Errorf("partial_total lost: %+v", got.Rules)
	}
	if got.Rules.HighRiskTotal != 2 {
		t.Errorf("high_risk_total lost — this is the number an admin is alerted on: %+v", got.Rules)
	}
	if got.Rules.VersionSkewTotal != 5 {
		t.Errorf("version_skew_total lost; without it a node running a stale ruleset is invisible: %+v", got.Rules)
	}
	if got.Rules.Executor != "absent" {
		t.Errorf("executor state lost: %+v", got.Rules)
	}
}

// TestPipelineHealth_DeepScanIsMountedOnFilterHook pins the mount point itself,
// because the design document named an endpoint that does not exist here.
func TestPipelineHealth_DeepScanIsMountedOnFilterHook(t *testing.T) {
	var fh FilterHookHealth
	fh.DeepScan = &DeepScanHealth{Mode: "off", Reason: "disabled", Status: "ok"}
	b, err := json.Marshal(fh)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	ds, ok := got["deepscan"].(map[string]any)
	if !ok {
		t.Fatalf("filter_hook carries no `deepscan` section: %s", b)
	}
	if ds["mode"] != "off" {
		t.Errorf("deepscan.mode = %v, want off", ds["mode"])
	}
	// A proxy with the lane off must still SAY so rather than omit the block:
	// "absent" and "off" are different answers to an operator's question.
	var none FilterHookHealth
	b2, _ := json.Marshal(none)
	if strings.Contains(string(b2), `"deepscan"`) {
		t.Errorf("an unset DeepScan must be omitted, not rendered empty: %s", b2)
	}
}
