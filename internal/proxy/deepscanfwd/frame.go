// Package deepscanfwd builds and delivers the asynchronous scan task frames the
// proxy sends to a scan node (TLS) or to the on-machine daemon (unix socket).
//
// It owns the OUTBOUND half only. What comes back is merged by
// internal/proxy/asyncscan, which is where identity gets stamped and events get
// built — a split that exists because the two halves have different security
// properties: this package decides what leaves the machine, that one decides
// what the org gets told.
//
// spec: R-scan-node-deepscan-3.S1 / R-scan-node-deepscan-8.S2 · design §3.1, §4b.2
package deepscanfwd

import (
	"unicode/utf8"

	"github.com/AiKeyLabs/pkg/deepscan"
	"github.com/AiKeyLabs/pkg/scanchunk"
)

// DefaultMaxPieceBytes caps one frame's content (design §4b.10,
// AIKEY_PROXY_DEEPSCAN_MAX_PIECE_BYTES). 256 KiB covers the overwhelming
// majority of real pieces while bounding both the frame and the queue's memory:
// the queue holds whole pieces, so this number multiplied by the queue depth is
// the worst case the proxy must survive.
const DefaultMaxPieceBytes = 256 * 1024

// PieceJob is one content piece the proxy decided to scan asynchronously.
//
// 🔴 It carries NO identity beyond the tenant, and no fast-layer spans. Identity
// is stamped onto the EVENT after the result returns (asyncscan.BuildEvents);
// spans are not available to the proxy at all — apphook.Response hands it offsets
// without categories by design (invariant #16), measured in baseline-forensics
// §F1 — so the node re-scans [0, HeadBytes) itself to get the equivalent list.
type PieceJob struct {
	JobID         string
	TenantID      string
	AuditUnitID   string
	ContentSHA256 string
	Source        string
	Text          string
	// HeadBytes is how many bytes the synchronous fast layer inspected. 0 when
	// the fast layer degraded and inspected nothing — in which case the async
	// lane must scan from the very beginning.
	HeadBytes int
	Engines   []string
	// DetectorVersion / ContentVersion are what THIS proxy's detector reports.
	// Carried on the job (not the frame) purely so the result can be compared
	// against them when it comes back: a receiver running a different ruleset
	// produces findings this machine's own detector would not, and an operator
	// needs that visible rather than inferred.
	DetectorVersion string
	ContentVersion  string
}

// Coverage is what the proxy will later report as the event's scan_coverage: how
// much of the piece was actually looked at, and why it was not all of it.
type Coverage struct {
	Status       string
	Reason       string
	ScannedBytes int
	TotalBytes   int
}

// BuildFrame assembles the task frame for one piece and returns the coverage the
// truncation decision implies.
//
// 🔴 Coverage is returned HERE, at the moment the content is cut, rather than
// derived later from the result. The node can only report on what it received;
// if the proxy dropped the tail and then trusted the node's "complete", the audit
// record would assert that bytes nobody ever looked at were clean. That is the
// precise failure this lane exists to fix — the fast layer truncated at 16 KiB
// for a year and said nothing (bugfix 20260813-pipe-input-cap-truncates-silently).
func BuildFrame(p PieceJob, token string, maxBytes int) (deepscan.FrameV2, Coverage) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPieceBytes
	}
	total := len(p.Text)
	prompt := p.Text
	cov := Coverage{Status: deepscan.StatusComplete, ScannedBytes: total, TotalBytes: total}

	if total > maxBytes {
		cut := runeStartAtOrBefore(p.Text, maxBytes)
		prompt = p.Text[:cut]
		cov = Coverage{
			Status:       deepscan.StatusPartial,
			Reason:       deepscan.ReasonPieceCap,
			ScannedBytes: len(prompt),
			TotalBytes:   total,
		}
	}

	head := p.HeadBytes
	if head > len(prompt) {
		head = len(prompt)
	}

	// Rule chunks are computed here, once, and travel inside the frame: the
	// receiver (Go locally, Python on a node) only slices what it was told to.
	// Starting one overlap BEFORE head_bytes is what keeps an entity straddling
	// the fast layer's edge visible to the async layer.
	// 🔴 No tail, no rule work. When the fast layer already covered the whole
	// piece (head == len(prompt) — every piece at or under the 16 KiB sync cap),
	// chunking from head-overlap would emit one chunk over bytes the fast layer
	// just scanned, and head dedup (design §3.6: drop findings with end <=
	// head_bytes) would then discard every finding it produced. That is a node
	// round-trip, a detector invocation and a queue slot spent to reach a
	// guaranteed-empty result — on the most common piece size there is.
	// spec: R-scan-node-deepscan-16.S3 · fence: TestDeepScanFrame_ShortPieceHasNoRuleChunks
	var chunks []scanchunk.Range
	if wantsEngine(p.Engines, deepscan.EngineRules) && head < len(prompt) {
		start := head - scanchunk.OverlapDefault
		if start < 0 {
			start = 0
		}
		chunks = scanchunk.Chunks(prompt, start, scanchunk.SizeBytes, scanchunk.OverlapDefault)
	}

	return deepscan.FrameV2{
		Version:       int(deepscan.FrameVersionV2),
		JobID:         p.JobID,
		Token:         token,
		TenantID:      p.TenantID,
		AuditUnitID:   p.AuditUnitID,
		ContentSHA256: p.ContentSHA256,
		Source:        p.Source,
		HeadBytes:     head,
		Engines:       p.Engines,
		RuleChunks:    chunks,
		Prompt:        prompt,
	}, cov
}

func wantsEngine(engines []string, want string) bool {
	for _, e := range engines {
		if e == want {
			return true
		}
	}
	return false
}

// runeStartAtOrBefore returns the largest index <= i that begins a UTF-8 rune,
// so a truncated prompt is still valid UTF-8 for the regex engine on the far side.
func runeStartAtOrBefore(s string, i int) int {
	if i <= 0 {
		return 0
	}
	if i >= len(s) {
		return len(s)
	}
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}
