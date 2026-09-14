// deepscan_health.go — the externally readable health block for the asynchronous
// deep-scan / rule back-scan lane.
//
// 🔴 WHY THIS BLOCK EXISTS AT ALL. The async lane changes nothing a user can see:
// it does not mask, does not block, does not alter a single forwarded byte. It
// only writes audit rows. That means a lane which silently stopped working looks
// EXACTLY like a lane with nothing to report — and the difference is the whole
// compliance guarantee. So every way this lane can lose coverage gets a counter
// here: dropped before delivery, failed in delivery, truncated at the cap,
// skipped because there was nowhere to send it, finished only partially.
// 健康信号必须可被外部读取.
//
// MOUNT POINT (baseline-forensics §F6, 2026-09-11): hangs off
// PipelineHealth.FilterHook on GET /v1/diagnostics/pipeline. The design document
// said `GET /admin/apps/health`, but that endpoint serves the app-pipeline
// last-call cache (apppipe.AppHealth: app_slug / status_code / error_type) and
// has no compliance entry to hang anything on. Additive block on an existing
// endpoint rather than a new route, for the same reason MaskRestore and
// FilterHook were (慎重新建 API/接口协议).
//
// spec: R-scan-node-deepscan-9.S1 / .S2 / R-scan-node-deepscan-22.S3 · design §4b.3
package proxy

// DeepScanHealth is the `deepscan` section under filter_hook.
type DeepScanHealth struct {
	// Mode is remote / local / off.
	Mode string `json:"mode"`
	// Reason says WHY the lane is in that mode, in terms an operator can act on:
	// ok / no_nodes / insecure_control_plane / local_daemon_absent / disabled.
	// "0 nodes" without a reason sends someone to read source code.
	Reason string `json:"reason"`
	// Status is ok / degraded (three consecutive delivery failures).
	Status string               `json:"status"`
	Nodes  []DeepScanNodeHealth `json:"nodes,omitempty"`

	DeepScanCounters

	Skipped DeepScanSkipped `json:"skipped_total"`
	// CoverageUnsupportedTotal counts events sent to a master too old to accept
	// scan_coverage. Non-zero means the audit records cannot distinguish
	// "scanned it all" from "ran out of budget" — a silent downgrade of the
	// guarantee that would otherwise be invisible.
	CoverageUnsupportedTotal uint64 `json:"coverage_unsupported_total"`

	// BGE is ABSENT (nil), not zeroed, when no on-machine daemon is installed.
	// 🔴 0 and "not running" must not render identically: a zero reads as "we
	// looked and found nothing", which is the reassuring direction to be wrong in.
	BGE *AsyncBGEHealth `json:"bge,omitempty"`
	// Rules is the rule back-scan lane, which runs even with no daemon.
	Rules *AsyncRulesHealth `json:"rules,omitempty"`
}

// DeepScanNodeHealth is one node's entry.
type DeepScanNodeHealth struct {
	ID      string `json:"id"`
	Breaker string `json:"breaker"` // closed / open
}

// DeepScanCounters are process-lifetime totals, embedded flat per design §4b.3.
type DeepScanCounters struct {
	EnqueuedTotal     uint64 `json:"enqueued_total"`
	DroppedTotal      uint64 `json:"dropped_total"`
	DroppedBytesTotal uint64 `json:"dropped_bytes_total"`
	ForwardedTotal    uint64 `json:"forwarded_total"`
	FailedTotal       uint64 `json:"failed_total"`
	// TruncatedTotal counts pieces cut at the per-piece cap. Those events carry
	// scan_coverage=partial; this is the fleet-level version of the same fact.
	TruncatedTotal uint64 `json:"truncated_total"`
	QueueLen       int    `json:"queue_len"`
}

// DeepScanSkipped breaks down work that was never enqueued, BY REASON.
//
// The breakdown is the point: `scanned` (the piece was already done — healthy)
// and `no_nodes` (there was nowhere to send it — a coverage hole) are opposite
// situations that a single "skipped" counter would blend into one reassuring
// number.
type DeepScanSkipped struct {
	NoNodes uint64 `json:"no_nodes"`
	Scanned uint64 `json:"scanned"`
	Blocked uint64 `json:"blocked"`
}

// AsyncBGEHealth is the semantic-recall lane's counters. Present only where a
// daemon actually runs.
type AsyncBGEHealth struct {
	CompletedTotal uint64 `json:"completed_total"`
	PartialTotal   uint64 `json:"partial_total"`
	DroppedTotal   uint64 `json:"dropped_total"`
}

// AsyncRulesHealth is the rule back-scan lane's counters.
type AsyncRulesHealth struct {
	CompletedTotal uint64 `json:"completed_total"`
	// PartialTotal counts results that finished but did not cover everything.
	PartialTotal uint64 `json:"partial_total"`
	// HighRiskTotal counts findings the synchronous policy WOULD have blocked
	// had it seen them. This is the number an admin is alerted on.
	HighRiskTotal uint64 `json:"high_risk_total"`
	DroppedTotal  uint64 `json:"dropped_total"`
	// VersionSkewTotal counts results produced by a ruleset different from this
	// proxy's. Without it, a node quietly running a stale ruleset is invisible.
	VersionSkewTotal uint64 `json:"version_skew_total"`
	// Executor is idle / running / absent for the on-machine background pool.
	Executor string `json:"executor"`
}
