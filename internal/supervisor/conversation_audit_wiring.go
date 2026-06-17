package supervisor

// conversation_audit_wiring.go — wires the conversation-audit observer (capture)
// to the content outbox (WAL → seq allocator → content reporter). This is the
// supervisor-side bridge: it imports both the decoupled observer package
// (which knows nothing about events.ContentWAL/SeqAllocator/ContentReporter) and
// the events package, exactly as ndjson_fanout's vault bridge does.
//
// The feature is a Cluster/team capability: it wires ONLY when the deployment
// has a team collector destination (a collector_routes["team"] URL and/or a
// "team" credential). The credential is OPTIONAL — Cluster worker proxies report
// to the internal collector over network trust with no credential. Personal/
// offline deployments (no team route/cred) leave the observer unbuilt (SetDeps
// with a nil sink → build() skips it), so they pay nothing.

import (
	"encoding/json"
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observer/conversation_audit"
)

// conversationAuditSink implements conversation_audit.RecordSink, bridging an
// assembled record to the content outbox. Lazy-attach: the observer is built
// early in buildGeneration (the framework reads observer deps at BuildObservers
// time), before the content outbox is constructed later in the SAME synchronous,
// pre-serving buildGeneration pass — so the sink starts unattached and attach()
// wires the real outbox once it exists. A Submit before attach (impossible in
// practice: no requests flow during buildGeneration) drops safely.
type conversationAuditSink struct {
	mu       sync.RWMutex
	wal      *events.ContentWAL
	seqAlloc *events.SeqAllocator
	reporter *events.ContentReporter
	sourceID string
	logger   *slog.Logger
}

func newConversationAuditSink(logger *slog.Logger) *conversationAuditSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &conversationAuditSink{logger: logger}
}

func (s *conversationAuditSink) attach(wal *events.ContentWAL, seqAlloc *events.SeqAllocator, reporter *events.ContentReporter, sourceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wal = wal
	s.seqAlloc = seqAlloc
	s.reporter = reporter
	s.sourceID = sourceID
}

// Submit stamps source_id/source_seq, marshals, appends to the content WAL, and
// pokes the reporter. Runs on the observer's per-request goroutine (off the hot
// path). Every failure degrades to a dropped record + WARN — it must never block
// or panic the caller. source_seq is allocated here (reserve-ahead) so it is
// stamped into BOTH the record JSON (collector reads it) and the WAL envelope
// (reporter cursor) consistently.
func (s *conversationAuditSink) Submit(rec *conversation_audit.ConversationRecord) {
	s.mu.RLock()
	wal, seqAlloc, reporter, sourceID := s.wal, s.seqAlloc, s.reporter, s.sourceID
	s.mu.RUnlock()
	if wal == nil || seqAlloc == nil || rec == nil {
		return // unattached (no team collector) — drop safely
	}
	seq, err := seqAlloc.Next()
	if err != nil {
		s.logger.Warn("conversation audit: seq alloc failed, dropping record",
			"event.name", "conversation.capture.seqalloc_failed",
			"error.code", "CONTENT_SEQALLOC_FAILED", "error", err)
		return
	}
	rec.SourceID = sourceID
	rec.SourceSeq = &seq
	b, err := json.Marshal(rec)
	if err != nil {
		s.logger.Warn("conversation audit: marshal failed, dropping record",
			"event.name", "conversation.capture.marshal_failed",
			"error.code", "CONTENT_MARSHAL_FAILED", "error", err)
		return
	}
	wal.Append(sourceID, seq, b)
	if reporter != nil {
		reporter.Poke()
	}
}

// wireConversationAudit constructs the content outbox (WAL + seq allocator +
// content reporter) under a `conversation/` subdir of the usage WAL dir (so the
// usage WAL's retention/archival never touches conv files and vice-versa) and
// attaches it to sink. Returns the pieces for the generation to Close on
// teardown, or zeroes when prerequisites are missing (capture stays off).
func wireConversationAudit(
	walBaseDir, collectorURL, sourceID, proxyInstanceID string,
	teamCred events.Credential,
	collectorToken string,
	sink *conversationAuditSink,
	logger *slog.Logger,
) (*events.ContentWAL, *events.SeqAllocator, *events.ContentReporter) {
	if logger == nil {
		logger = slog.Default()
	}
	// Auth MIRRORS the usage reporter: Personal/lobster nodes carry a per-route
	// team Credential (vault JWT); Cluster worker nodes have NO team credential
	// and authenticate the collector with the static collectorToken (cluster
	// service token from cluster-node.env). doUpload tries Credential then
	// collectorToken; both empty = network-trust (no Authorization). Only the
	// collector destination + sink are mandatory.
	if walBaseDir == "" || collectorURL == "" || sink == nil {
		return nil, nil, nil
	}
	convDir := filepath.Join(walBaseDir, "conversation")
	wal, err := events.NewContentWAL(convDir, 0, 0) // defaults: 20MB/file, 100 files
	if err != nil {
		logger.Warn("conversation audit: content WAL init failed, capture disabled",
			"event.name", "conversation.outbox.wal_init_failed",
			"error.code", "CONTENT_WAL_INIT_FAILED", "error", err)
		return nil, nil, nil
	}
	seqAlloc, err := events.NewSeqAllocator(filepath.Join(convDir, "content_seq.state"), events.DefaultSeqBlockSize)
	if err != nil {
		logger.Warn("conversation audit: content seq allocator init failed, capture disabled",
			"event.name", "conversation.outbox.seqalloc_init_failed",
			"error.code", "CONTENT_SEQALLOC_INIT_FAILED", "error", err)
		_ = wal.Close()
		return nil, nil, nil
	}
	reporter := events.NewContentReporter(events.ContentReporterConfig{
		CollectorURL:    collectorURL,
		Credential:      teamCred,
		CollectorToken:  collectorToken,
		ProxyInstanceID: proxyInstanceID,
		SeqAlloc:        seqAlloc,
	}, wal)
	reporter.Start()
	sink.attach(wal, seqAlloc, reporter, sourceID)
	logger.Info("conversation audit: outbox wired",
		"event.name", "conversation.outbox.wired", "collector_url", collectorURL)
	return wal, seqAlloc, reporter
}
