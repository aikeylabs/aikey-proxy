package asyncscan

import (
	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/pkg/deepscan"
	"github.com/AiKeyLabs/pkg/scanchunk"
)

// Scenario values for asynchronous events (design §4b.6). They are what the
// audit page filters on, so they are a user-visible contract.
const (
	// ScenarioAsyncDeepAudit — a semantic-recall (bge) finding.
	ScenarioAsyncDeepAudit = "async_deep_audit"
	// ScenarioAsyncRuleAudit — a rule finding that would NOT have been blocked
	// even if the synchronous layer had seen it.
	ScenarioAsyncRuleAudit = "async_rule_audit"
	// ScenarioAsyncRuleLeak — a rule finding that WOULD have been blocked. The
	// content reached the model because nobody looked in time. This is the only
	// value that means "an incident happened".
	ScenarioAsyncRuleLeak = "async_rule_leak"
)

// MergedResult is one piece's asynchronous outcome, ready to become events.
type MergedResult struct {
	Job         PieceJob
	Findings    []deepscan.Finding
	Coverage    Coverage
	Scenario    string
	ActionTaken string
	// WouldHaveBlocked is true when at least one finding falls in a range the
	// receiver judged `block` AND both ceilings would have permitted a block.
	WouldHaveBlocked bool
	// VersionSkew is true when the result was produced by a different ruleset or
	// detector build than this proxy runs.
	VersionSkew bool
}

// Coverage mirrors what will be reported as the event's scan_coverage.
type Coverage struct {
	Status string `json:"status"`
	// Reason is proxy-internal: it decides whether the piece is finished
	// (Finalize), and master has no column for it.
	Reason       string `json:"-"`
	ScannedBytes int    `json:"scanned_bytes"`
	TotalBytes   int    `json:"total_bytes"`
}

// Merge turns a receiver's result into the proxy's verdict about one piece.
//
// It does three things the receiver cannot do, because it knows things the
// receiver was deliberately never told:
//
//  1. HEAD DEDUP. Findings ending at or before head_bytes were already reported
//     by the synchronous layer. Keeping them files the same credential twice per
//     turn under two event ids that no database constraint can collapse.
//     A finding that STRADDLES head_bytes is KEPT: the fast layer saw only its
//     first half and therefore reported nothing, so this lane is the only place
//     the whole entity is ever seen. That case is exactly what the 2048-byte
//     chunk overlap exists to produce (baseline-forensics §F8 ①).
//
//  2. HIGH-RISK JUDGEMENT. "Would this have been blocked?" depends on THIS
//     machine's policy ceilings, which the node does not have and must not be
//     given. See wouldHaveBlocked.
//
//  3. VERSION SKEW. Whether the answer came from the same ruleset this proxy
//     runs.
//
// pieceCeiling is the cap for this kind of content (plain text = block-capable,
// tool_result = audit-only); deployCeiling is the org-wide filter_max_action.
func Merge(job PieceJob, r deepscan.ResultFrame, pieceCeiling, deployCeiling apphook.Action) MergedResult {
	m := MergedResult{Job: job, ActionTaken: "audit"}

	kept := make([]deepscan.Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		// end <= head_bytes ⇒ wholly inside what the fast layer already scanned.
		if f.End <= job.HeadBytes {
			continue
		}
		kept = append(kept, f)
	}
	// Collapse the duplicates the chunk overlap creates, through the same merge
	// the chunker owns — one implementation of "same entity, same span".
	m.Findings = scanchunk.MergeFindings([]scanchunk.ChunkFindings{{Findings: kept}})

	m.Coverage = Coverage{
		Status:       r.Status,
		Reason:       r.Reason,
		ScannedBytes: r.ScannedBytes,
		TotalBytes:   r.TotalBytes,
	}
	if m.Coverage.Status == "" {
		m.Coverage.Status = deepscan.StatusComplete
	}
	if m.Coverage.TotalBytes == 0 {
		m.Coverage.TotalBytes = len(job.Text)
	}

	m.VersionSkew = versionSkew(job, r)
	m.WouldHaveBlocked = wouldHaveBlocked(m.Findings, r.RuleVerdicts, pieceCeiling, deployCeiling)

	switch {
	case m.WouldHaveBlocked:
		m.Scenario = ScenarioAsyncRuleLeak
	default:
		m.Scenario = ScenarioAsyncRuleAudit
	}
	return m
}

// wouldHaveBlocked answers "if the synchronous layer had seen these bytes, would
// the request have been refused?"
//
// 🔴 THIS IS A JUDGEMENT ABOUT THE PROXY'S OWN POLICY, NOT ABOUT THE FINDING.
// It is computed here, never on the node, for two reasons. First, the node does
// not have this machine's ceilings and must not be given them — they are policy,
// and policy on a shared box is a thing to be tampered with. Second, the answer
// decides whether an admin sees an INCIDENT, and an incident queue that fills
// with cases where the product behaved exactly as designed is a queue nobody
// reads.
//
// Three gates, all of which must permit a block:
//
//	the receiver judged the range `block`  — the rule itself is a blocking rule
//	pieceCeiling permits block             — e.g. tool_result is pinned to audit
//	                                         (2026-08-10 方案②), so even a seen
//	                                         block there would only be recorded
//	deployCeiling permits block            — the org's filter_max_action; if it
//	                                         is warn, nothing is ever blocked
//	                                         anywhere, so nothing can be a leak
func wouldHaveBlocked(findings []deepscan.Finding, verdicts []deepscan.RangeVerdict, pieceCeiling, deployCeiling apphook.Action) bool {
	if severityRank(pieceCeiling) < severityRank(apphook.ActionBlock) {
		return false
	}
	if severityRank(deployCeiling) < severityRank(apphook.ActionBlock) {
		return false
	}
	for _, f := range findings {
		for _, v := range verdicts {
			// 🔴 `answer` is a refusal too. It arrived with compliance grading on
			// develop-v1.0.7, after this function was written: a tail hit whose rule
			// serves a canned answer would otherwise never be reported as the leak
			// it is, because only the literal "block" was checked.
			if v.Action != apphook.ActionBlock.String() && v.Action != apphook.ActionAnswer.String() {
				continue
			}
			// The finding must lie inside a range the receiver judged block.
			if f.Start >= v.Start && f.End <= v.End {
				return true
			}
		}
	}
	return false
}

// severityRank orders actions by how much they INTERFERE: allow < warn < mask <
// block. Deliberately not apphook.Action's numeric order (Allow=0, Mask=1,
// Block=2, Warn=3), which is an identifier space, not a ladder — comparing those
// integers would rank warn above block.
func severityRank(a apphook.Action) int {
	switch a {
	case apphook.ActionBlock, apphook.ActionAnswer:
		// A canned answer REFUSES the request exactly as a block does (apphook:
		// "refuses the request like ActionBlock"); it only differs in what the
		// client reads. For "would this have been stopped?" the two are one rung.
		return 3
	case apphook.ActionMask:
		return 2
	case apphook.ActionWarn:
		return 1
	case apphook.ActionAllow:
		return 0
	default:
		// An unknown action ranks lowest, so an unrecognized ceiling can never be
		// read as permission to call something a leak.
		return 0
	}
}

// versionSkew reports whether the result came from a different ruleset or
// detector build than this proxy runs. Empty on either side means "not stated",
// which is not skew — an older receiver simply does not report versions.
func versionSkew(job PieceJob, r deepscan.ResultFrame) bool {
	got := r.Engines.Rules
	if job.DetectorVersion != "" && got.DetectorVersion != "" && job.DetectorVersion != got.DetectorVersion {
		return true
	}
	if job.ContentVersion != "" && got.ContentVersion != "" && job.ContentVersion != got.ContentVersion {
		return true
	}
	return false
}
