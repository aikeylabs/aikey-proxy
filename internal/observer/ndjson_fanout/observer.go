// Package ndjson_fanout is the proxy-bundled first-party Observer that
// writes events from every SPEC §1.4.1 stream (user_chat / app_pipeline /
// probe) to per-subscriber NDJSON files. Subscribers declare their
// interest in vault `app_records.observe_streams`; this observer reads
// that view at Build time and constructs a per-(slug, stream) writer
// table.
//
// Architecture choice (vs the existing rhythm observer in
// ai-degrade-detector/proxy-plugin/rhythm/):
//
//   - rhythm = degrade-detector-specific in-process scorer + HTTP
//     reporter; only fires on app_pipeline traffic
//   - ndjson_fanout = generic file fanout for any vault-declared
//     subscriber; fires on all three streams
//
// They coexist via the SPEC §1.4 stream-based routing in
// pkg/observer.Registry — rhythm declares Streams=[app_pipeline], this
// declares Streams=AllStreams(), and the Registry filters per-event.
//
// Limitations (P3 step 2c MVP):
//
//   - **payload_level=full not yet supported** — subscribers requesting
//     full body get a startup WARN + downgrade to metadata-only.
//     Implementing full requires the StreamingObserver framework to expose
//     request/response bodies, which is a separate Phase work.
//   - **No file rotation yet** — files grow unbounded. Daily rotate +
//     7-day cleanup land as P3 follow-up (SPEC §1.4.4 contract).
//   - **No runtime subscriber refresh** — subscribers loaded once at
//     proxy startup; vault changes require restart. Matches existing
//     observer Build-once lifecycle.
package ndjson_fanout

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// VaultReader is the minimal vault surface this observer depends on.
// Defined as an interface so the test fixtures can supply a focused stub
// without spinning up real SQLite + schema.
type VaultReader interface {
	ListObserveSubscriptions() ([]observerSubscription, error)
}

// observerSubscription mirrors vault.ObserveSubscription byte-for-byte.
// Duplicated locally so this package's VaultReader interface can be
// defined without importing vault (which would invert the natural
// dependency: vault is an inner package, observers are outer).
// VaultGetter implementations adapt the real vault type into this
// local view — see adapter.go.
type observerSubscription struct {
	Slug         string
	Stream       string
	PayloadLevel string
}

// Event is the JSON line written to NDJSON files. Mirrors SPEC §1.4.1
// metadata payload. Body fields (RequestBody / ResponseBody) are
// reserved for future payload_level=full support — currently always
// omitted regardless of subscriber declaration.
//
// V=1 fixes the wire format; bumps require coordinated subscriber
// update.
type Event struct {
	V         int    `json:"v"`
	Stream    string `json:"stream"`
	TraceID   string `json:"trace_id"`
	TS        int64  `json:"ts_unix_ms"`
	Provider  string `json:"provider,omitempty"`
	Alias     string `json:"alias,omitempty"`
	AppSlug   string `json:"app_slug,omitempty"`
	AppKeyID  string `json:"app_key_id,omitempty"`
	Model     string `json:"model,omitempty"`
	NChunks   int    `json:"n_chunks,omitempty"`
	LatencyMs int    `json:"latency_ms,omitempty"`
	Status    string `json:"status,omitempty"` // "ok" | "ended" | ...
}

// EventFromContext builds the metadata Event for one request from the
// observer's RequestContext + per-request running counters.
//
// Exposed as a top-level function (not a method on *fanoutObserver) so
// future observers in the same package — or callers that just want the
// canonical serialization shape — can reuse the mapping without
// instantiating the writer.
func EventFromContext(req *observer.RequestContext, nChunks, latencyMs int, status string) Event {
	model := req.ResolvedModel
	if model == "" {
		model = req.RequestedModel
	}
	return Event{
		V:         1,
		Stream:    req.Stream,
		TraceID:   req.TraceID,
		TS:        time.Now().UnixMilli(),
		Provider:  req.ProviderID,
		Alias:     req.KeyAlias,
		AppSlug:   req.AppSlug,
		AppKeyID:  req.AppKeyID,
		Model:     model,
		NChunks:   nChunks,
		LatencyMs: latencyMs,
		Status:    status,
	}
}

// fanoutObserver implements observer.StreamingObserver. One instance per
// proxy generation; per-request state lives in the in-memory `state` map
// keyed by TraceID.
type fanoutObserver struct {
	logger *slog.Logger

	// baseDir is the on-disk root for per-subscriber files. Default
	// `~/.aikey/data/observers/`; overrideable via Build cfg for tests.
	baseDir string

	// routing maps stream name → list of (slug, file handle) for active
	// subscribers. Built once at Build time; never mutated afterwards
	// (no runtime subscriber refresh in MVP).
	routing map[string][]*writerEntry

	// state tracks per-request running counters between OnRequestStart
	// and OnRequestEnd. Keyed by TraceID.
	stateMu sync.Mutex
	state   map[string]*requestState
}

type writerEntry struct {
	slug   string
	path   string
	muFile sync.Mutex // serialize writes to a single file handle
	file   *os.File
}

type requestState struct {
	startedAt time.Time
	nChunks   int
}

// New constructs an unstarted fanoutObserver. Build() (in registration.go)
// is the production entry point; tests use New directly so they can
// inject a custom baseDir + a stubbed VaultReader.
func New(logger *slog.Logger, baseDir string, reader VaultReader) (observer.StreamingObserver, error) {
	if logger == nil {
		logger = slog.Default().With(slog.String("component", "ndjson-fanout"))
	}
	if baseDir == "" {
		return nil, fmt.Errorf("ndjson_fanout: baseDir must be non-empty")
	}

	subs, err := reader.ListObserveSubscriptions()
	if err != nil {
		return nil, fmt.Errorf("ndjson_fanout: read subscribers: %w", err)
	}

	// MVP: payload_level=full not yet supported. Surface a WARN per
	// affected subscriber so the user (or operator) knows their
	// declaration is being effectively downgraded.
	for _, s := range subs {
		if s.PayloadLevel == "full" {
			logger.Warn("ndjson_fanout: payload_level=full not yet supported; "+
				"subscriber will receive metadata only (SPEC §1.4.2 full-body "+
				"path is reserved for future Phase work)",
				"event.name", "ndjson_fanout.full_unsupported",
				"slug", s.Slug,
				"stream", s.Stream,
			)
		}
	}

	routing := map[string][]*writerEntry{}
	for _, s := range subs {
		// Validate stream name against the SPEC vocabulary so a typo in
		// vault (e.g. `user-chat` with hyphen) is caught at startup
		// rather than silently routing nowhere.
		if !knownStream(s.Stream) {
			logger.Warn("ndjson_fanout: skipping subscription with unknown stream",
				"event.name", "ndjson_fanout.unknown_stream",
				"slug", s.Slug,
				"stream", s.Stream,
				"valid_streams", observer.AllStreams(),
			)
			continue
		}
		path, err := ensureSubscriberFile(baseDir, s.Slug, s.Stream)
		if err != nil {
			logger.Warn("ndjson_fanout: cannot open file for subscriber, skipping",
				"event.name", "ndjson_fanout.file_open_failed",
				"slug", s.Slug,
				"stream", s.Stream,
				"error", err.Error(),
			)
			continue
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			logger.Warn("ndjson_fanout: cannot open NDJSON file, skipping",
				"event.name", "ndjson_fanout.file_open_failed",
				"slug", s.Slug,
				"path", path,
				"error", err.Error(),
			)
			continue
		}
		entry := &writerEntry{slug: s.Slug, path: path, file: f}
		routing[s.Stream] = append(routing[s.Stream], entry)
		logger.Info("ndjson_fanout: subscriber wired",
			"event.name", "ndjson_fanout.subscriber_wired",
			"slug", s.Slug,
			"stream", s.Stream,
			"path", path,
		)
	}

	totalSubs := 0
	for _, es := range routing {
		totalSubs += len(es)
	}
	if totalSubs == 0 {
		logger.Info("ndjson_fanout: no active subscribers — observer will noop",
			"event.name", "ndjson_fanout.noop_no_subscribers")
	}

	return &fanoutObserver{
		logger:  logger,
		baseDir: baseDir,
		routing: routing,
		state:   map[string]*requestState{},
	}, nil
}

// ensureSubscriberFile creates the per-subscriber directory under baseDir
// and returns the NDJSON file path. Path convention from SPEC §1.4.4:
//
//	<baseDir>/<slug>/<stream>.ndjson
func ensureSubscriberFile(baseDir, slug, stream string) (string, error) {
	dir := filepath.Join(baseDir, slug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return filepath.Join(dir, stream+".ndjson"), nil
}

// knownStream is a guard against typo'd vault entries. Mirrors
// observer.AllStreams() so adding a new stream requires both updating the
// framework AND this whitelist (forcing alignment).
func knownStream(s string) bool {
	for _, ok := range observer.AllStreams() {
		if s == ok {
			return true
		}
	}
	return false
}

// OnRequestStart records a per-trace state entry so OnRequestEnd can
// compute total latency + chunk count. Cheap (one map write); the heavy
// file IO happens in OnRequestEnd.
//
// We skip work entirely when no subscriber routes for this stream — the
// per-event allocation is already non-trivial, no point spending it.
func (o *fanoutObserver) OnRequestStart(ctx context.Context, req *observer.RequestContext) {
	if req == nil {
		return
	}
	if len(o.routing[req.Stream]) == 0 {
		return // no subscribers care; skip state allocation
	}
	o.stateMu.Lock()
	o.state[req.TraceID] = &requestState{startedAt: time.Now()}
	o.stateMu.Unlock()
}

// OnSSEEvent increments the per-trace n_chunks counter so OnRequestEnd's
// emitted Event reflects the streaming density. We don't write per-frame
// to NDJSON (would be too noisy for downstream readers; one line per
// request is the SPEC §1.4 contract).
func (o *fanoutObserver) OnSSEEvent(ctx context.Context, req *observer.RequestContext, eventType string, payload []byte) {
	if req == nil {
		return
	}
	o.stateMu.Lock()
	rs, ok := o.state[req.TraceID]
	if ok {
		rs.nChunks++
	}
	o.stateMu.Unlock()
}

// OnRequestEnd writes one Event JSON line to every subscriber file
// registered for this request's stream. Failures (IO errors, locked
// files, etc.) are logged WARN and dropped — fail-open per SPEC §1.4.5,
// the proxy main path must not be impacted by observer issues.
func (o *fanoutObserver) OnRequestEnd(ctx context.Context, req *observer.RequestContext, totalLatencyMs int) {
	if req == nil {
		return
	}
	entries := o.routing[req.Stream]
	if len(entries) == 0 {
		return
	}

	o.stateMu.Lock()
	rs, ok := o.state[req.TraceID]
	delete(o.state, req.TraceID)
	o.stateMu.Unlock()

	nChunks := 0
	if ok {
		nChunks = rs.nChunks
	}

	ev := EventFromContext(req, nChunks, totalLatencyMs, "ended")
	line, err := json.Marshal(ev)
	if err != nil {
		// Should be impossible — Event has no exotic fields. Log + drop.
		o.logger.Warn("ndjson_fanout: event marshal failed",
			"event.name", "ndjson_fanout.marshal_failed",
			"trace_id", req.TraceID,
			"error", err.Error(),
		)
		return
	}
	line = append(line, '\n')

	for _, e := range entries {
		// entries holds *writerEntry, so each e shares the one canonical
		// per-file mutex (no value copy of the lock — see writerEntry).
		writeToSubscriber(o.logger, e, line, req.TraceID)
	}
}

// writeToSubscriber writes one event line to a subscriber's file under
// a per-file mutex. Append-only, fsync deferred (OS write cache is fine
// for trust-local tail reading — SPEC §1.4.5 backs off on durability for
// the sake of zero main-path impact).
func writeToSubscriber(logger *slog.Logger, e *writerEntry, line []byte, traceID string) {
	e.muFile.Lock()
	defer e.muFile.Unlock()
	if _, err := e.file.Write(line); err != nil {
		logger.Warn("ndjson_fanout: write failed (event dropped)",
			"event.name", "ndjson_fanout.write_failed",
			"slug", e.slug,
			"path", e.path,
			"trace_id", traceID,
			"error", err.Error(),
		)
	}
}
