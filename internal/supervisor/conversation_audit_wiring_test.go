package supervisor

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observer/conversation_audit"
)

// The sink must stamp source_id/source_seq into BOTH the WAL envelope (reporter
// cursor) and the record JSON (collector ingest) consistently, and tolerate a
// nil reporter.
func TestConversationAuditSink_StampsAndAppends(t *testing.T) {
	dir := t.TempDir()
	wal, err := events.NewContentWAL(dir, 0, 0)
	if err != nil {
		t.Fatalf("content wal: %v", err)
	}
	defer wal.Close()
	sa, err := events.NewSeqAllocator(filepath.Join(dir, "seq.state"), events.DefaultSeqBlockSize)
	if err != nil {
		t.Fatalf("seq allocator: %v", err)
	}
	defer sa.Close()

	sink := newConversationAuditSink(nil)
	sink.attach(wal, sa, nil, "src-1") // nil reporter — Submit must tolerate it

	sink.Submit(&conversation_audit.ConversationRecord{
		EventID: "ev-1", OrgID: "org-1", SessionID: "s-1", OwnerAccountID: "acct-1",
		UserText: "hello", AssistantText: "hi", RequestStatus: "ok",
	})
	wal.Sync()

	entries, err := events.ReadAllContentWAL(wal.Dir())
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d want 1", len(entries))
	}
	e := entries[0]
	if e.SourceID != "src-1" || e.SourceSeq == 0 {
		t.Fatalf("WAL envelope source_id=%q seq=%d want src-1/non-zero", e.SourceID, e.SourceSeq)
	}
	// The record JSON must carry the SAME source_id/source_seq the collector reads.
	var rec conversation_audit.ConversationRecord
	if err := json.Unmarshal(e.Record, &rec); err != nil {
		t.Fatalf("record unmarshal: %v", err)
	}
	if rec.SourceID != "src-1" || rec.SourceSeq == nil || *rec.SourceSeq != e.SourceSeq {
		t.Fatalf("record source mismatch: id=%q seq=%v vs envelope seq=%d", rec.SourceID, rec.SourceSeq, e.SourceSeq)
	}
	if rec.UserText != "hello" || rec.AssistantText != "hi" {
		t.Fatalf("content not preserved through sink: %+v", rec)
	}
}

// Submit before attach (Personal/offline — no team collector) must drop safely,
// never panic.
func TestConversationAuditSink_UnattachedDropsSafely(t *testing.T) {
	sink := newConversationAuditSink(nil)
	sink.Submit(&conversation_audit.ConversationRecord{EventID: "x"}) // no-op, no panic
}

// Cluster regression (2026-06-17): the worker proxy reports to the internal
// collector with NO team credential (network trust over the VPC) — its config
// has collector_routes["team"] but no collector_credentials["team"].
// wireConversationAudit MUST still wire when teamCred is nil. The original gate
// required a non-nil team credential, which silently disabled capture on the
// Cluster edition — the very edition this feature targets. ContentReporter
// .doUpload omits the Authorization header when Credential is nil, identical to
// the usage reporter (which already tolerates the credential-less cluster case).
// Bugfix: workflow/CI/bugfix/2026-06-17-conversation-audit-cluster-nil-cred-gate.md
func TestWireConversationAudit_NilCredStillWires(t *testing.T) {
	dir := t.TempDir()
	sink := newConversationAuditSink(nil)
	// nil teamCred + a (team) collector URL + sink → must wire.
	// 127.0.0.1:1 → instant connection-refused so Close() doesn't block on an
	// in-flight upload timeout (keeps this fence fast). nil cred + "" token =
	// network-trust deployment — must still wire (capture stays on).
	wal, sa, rep := wireConversationAudit(dir, "http://127.0.0.1:1", "src-1", "proxy-0", nil, "", sink, nil)
	if wal == nil || sa == nil || rep == nil {
		t.Fatalf("nil-credential (Cluster) deployment must still wire: wal=%v sa=%v rep=%v", wal, sa, rep)
	}
	defer func() { _ = rep.Close(); _ = wal.Close(); _ = sa.Close() }()

	// The sink is attached: a Submit reaches the WAL (capture works credential-less).
	sink.Submit(&conversation_audit.ConversationRecord{
		EventID: "ev-1", OrgID: "o-1", SessionID: "s-1", OwnerAccountID: "a-1",
		UserText: "hi", AssistantText: "yo", RequestStatus: "ok",
	})
	wal.Sync()
	entries, err := events.ReadAllContentWAL(wal.Dir())
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("nil-cred wired sink should append 1 entry, got %d", len(entries))
	}
}
