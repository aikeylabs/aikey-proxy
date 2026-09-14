package deepscanfwd

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/AiKeyLabs/pkg/deepscan"
)

// TestDeepScanFrame_MinimalFieldsAndProxyStampsIdentity: the frame carries the
// least the node can do its job with, and identity is stamped by the PROXY onto
// the event afterwards — never sent to the node.
//
// The node is a shared box handling several employees' content and it uploads
// nothing. Giving it a seat id or a session id would tell a compromised node who
// said what, and buy exactly nothing in return. tenant_id is the one exception:
// without it the node cannot refuse another org's content.
func TestDeepScanFrame_MinimalFieldsAndProxyStampsIdentity(t *testing.T) {
	job := PieceJob{
		JobID:         "job-1",
		TenantID:      "org_a",
		AuditUnitID:   "au_cafebabe",
		ContentSHA256: "b1946ac92492d2347c6235b4d2611184",
		Source:        deepscan.SourceRequest,
		Text:          "客户手机号 13800138000 请核对",
		HeadBytes:     10,
		Engines:       []string{deepscan.EngineBGE, deepscan.EngineRules},
	}
	f, cov := BuildFrame(job, "sct1.org_a.1757620000.k1.abc", DefaultMaxPieceBytes)

	if f.TenantID != "org_a" || f.AuditUnitID != "au_cafebabe" || f.JobID != "job-1" {
		t.Fatalf("frame lost its routing fields: %+v", f)
	}
	if f.Token == "" {
		t.Error("frame carries no token — the node has nothing to authorize against")
	}
	if cov.Status != deepscan.StatusComplete {
		t.Errorf("a piece under the cap must be complete coverage, got %q", cov.Status)
	}
	if cov.ScannedBytes != len(job.Text) || cov.TotalBytes != len(job.Text) {
		t.Errorf("coverage bytes wrong: %+v (text %d bytes)", cov, len(job.Text))
	}

	b, err := deepscan.EncodeFrameV2(f)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	wire := string(b)
	for _, banned := range []string{"seat_id", "virtual_key_id", "session_id", "trace_id", "user_id", "spans"} {
		if strings.Contains(wire, banned) {
			t.Errorf("the frame put %q on the wire — identity is stamped by the proxy on the EVENT, never sent to a node", banned)
		}
	}
}

// TestDeepScanFrame_PieceCapMarksPartial: a piece over the cap is truncated, the
// cut lands on a rune boundary, and the coverage says `partial` with the reason.
//
// 🔴 The `partial` marker is the whole point. Truncating quietly is the exact bug
// this lane exists to fix — the fast layer already did that at 16 KiB for a year
// and nothing anywhere said so. A truncated piece reported as `complete` is
// worse than no scan at all, because the audit record then asserts the tail was
// clean.
func TestDeepScanFrame_PieceCapMarksPartial(t *testing.T) {
	const cap = 4096
	// CJK so a byte-wise cut almost certainly lands mid-rune.
	text := strings.Repeat("客户资料需要保密。", 2000)
	job := PieceJob{
		JobID: "job-2", TenantID: "org_a", AuditUnitID: "au_1", ContentSHA256: "x",
		Source: deepscan.SourceRequest, Text: text, Engines: []string{deepscan.EngineRules},
	}
	f, cov := BuildFrame(job, "tok", cap)

	if len(f.Prompt) > cap {
		t.Errorf("prompt is %d bytes, over the %d-byte cap", len(f.Prompt), cap)
	}
	if !utf8.ValidString(f.Prompt) {
		t.Error("the truncation cut a UTF-8 rune in half")
	}
	if cov.Status != deepscan.StatusPartial {
		t.Errorf("status = %q, want %q", cov.Status, deepscan.StatusPartial)
	}
	if cov.Reason != deepscan.ReasonPieceCap {
		t.Errorf("reason = %q, want %q", cov.Reason, deepscan.ReasonPieceCap)
	}
	if cov.TotalBytes != len(text) {
		t.Errorf("total_bytes = %d, want the FULL piece size %d — the number exists to say how much was NOT scanned",
			cov.TotalBytes, len(text))
	}
	if cov.ScannedBytes != len(f.Prompt) {
		t.Errorf("scanned_bytes = %d but the frame carries %d", cov.ScannedBytes, len(f.Prompt))
	}
	if cov.ScannedBytes >= cov.TotalBytes {
		t.Error("a partial coverage that claims it scanned everything is not partial")
	}
}

// TestDeepScanFrame_ChunksStartBeforeHeadBytes: rule chunks begin one overlap
// BEFORE the fast layer stopped, so an entity straddling that boundary is still
// seen whole (design §3.6).
func TestDeepScanFrame_ChunksStartBeforeHeadBytes(t *testing.T) {
	text := strings.Repeat("a", 80*1024)
	job := PieceJob{
		JobID: "job-3", TenantID: "org_a", AuditUnitID: "au_1", ContentSHA256: "x",
		Source: deepscan.SourceRequest, Text: text, HeadBytes: 16 * 1024,
		Engines: []string{deepscan.EngineRules},
	}
	f, _ := BuildFrame(job, "tok", DefaultMaxPieceBytes)
	if len(f.RuleChunks) == 0 {
		t.Fatal("a 80 KiB piece with a 16 KiB head produced no rule chunks")
	}
	first := f.RuleChunks[0]
	if first.Start >= job.HeadBytes {
		t.Errorf("first chunk starts at %d, at or after head_bytes %d — an entity on that boundary is invisible to both layers",
			first.Start, job.HeadBytes)
	}
	if job.HeadBytes-first.Start < 2048 {
		t.Errorf("first chunk starts only %d bytes before head_bytes; the overlap is 2048 (measured longest bounded rule = 1939B)",
			job.HeadBytes-first.Start)
	}
	if last := f.RuleChunks[len(f.RuleChunks)-1]; last.End != len(f.Prompt) {
		t.Errorf("last chunk ends at %d, not the end of the frame's prompt (%d)", last.End, len(f.Prompt))
	}
}

// TestDeepScanFrame_ShortPieceHasNoRuleChunks: the fast layer already covered it,
// so the async lane must produce no rule work at all (R-scan-node-deepscan-16.S3).
func TestDeepScanFrame_ShortPieceHasNoRuleChunks(t *testing.T) {
	text := strings.Repeat("a", 8000)
	job := PieceJob{
		JobID: "job-4", TenantID: "org_a", AuditUnitID: "au_1", ContentSHA256: "x",
		Source: deepscan.SourceRequest, Text: text, HeadBytes: len(text),
		Engines: []string{deepscan.EngineRules},
	}
	f, cov := BuildFrame(job, "tok", DefaultMaxPieceBytes)
	if len(f.RuleChunks) != 0 {
		t.Errorf("a fully fast-scanned piece produced %d rule chunks: %+v", len(f.RuleChunks), f.RuleChunks)
	}
	if cov.Status != deepscan.StatusComplete {
		t.Errorf("coverage = %q, want complete", cov.Status)
	}
}
