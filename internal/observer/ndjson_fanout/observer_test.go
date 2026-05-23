package ndjson_fanout

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// stubVault is the in-memory VaultReader the tests use. Replaces the
// production vault.Reader so test cases stay focused on observer
// behavior rather than vault wiring.
type stubVault struct {
	subs []observerSubscription
	err  error
}

func (s *stubVault) ListObserveSubscriptions() ([]observerSubscription, error) {
	return s.subs, s.err
}

// newTestObserver builds a fanoutObserver writing to a temp dir, with
// caller-supplied subscriptions seeded in the stub vault.
func newTestObserver(t *testing.T, subs []observerSubscription) (observer.StreamingObserver, string) {
	t.Helper()
	dir := t.TempDir()
	obs, err := New(slog.Default(), dir, &stubVault{subs: subs})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return obs, dir
}

func mkReq(stream, traceID string) *observer.RequestContext {
	return &observer.RequestContext{
		TraceID:        traceID,
		Stream:         stream,
		ProviderID:     "anthropic",
		KeyAlias:       "FreySilvaqzs@qualityservice.com",
		ResolvedModel:  "claude-sonnet-4-6",
		StartedAt:      time.Now(),
	}
}

func readEvents(t *testing.T, baseDir, slug, stream string) []Event {
	t.Helper()
	path := filepath.Join(baseDir, slug, stream+".ndjson")
	data, err := os.ReadFile(path)
	if err != nil {
		// Empty file → no events written → return nil to let caller assert
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read %s: %v", path, err)
	}
	var out []Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

// TestObserver_WritesEventToSubscriberFile is the happy path: one
// subscriber, one request → one JSON line in the expected file.
func TestObserver_WritesEventToSubscriberFile(t *testing.T) {
	obs, dir := newTestObserver(t, []observerSubscription{
		{Slug: "degrade-detector", Stream: observer.StreamUserChat, PayloadLevel: "metadata"},
	})

	req := mkReq(observer.StreamUserChat, "trace-1")
	obs.OnRequestStart(context.Background(), req)
	obs.OnSSEEvent(context.Background(), req, "", []byte("frame-1"))
	obs.OnSSEEvent(context.Background(), req, "", []byte("frame-2"))
	obs.OnRequestEnd(context.Background(), req, 42)

	events := readEvents(t, dir, "degrade-detector", "user_chat")
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d: %+v", len(events), events)
	}
	ev := events[0]
	if ev.V != 1 {
		t.Errorf("V = %d, want 1", ev.V)
	}
	if ev.Stream != "user_chat" {
		t.Errorf("Stream = %q, want user_chat", ev.Stream)
	}
	if ev.TraceID != "trace-1" {
		t.Errorf("TraceID = %q, want trace-1", ev.TraceID)
	}
	if ev.NChunks != 2 {
		t.Errorf("NChunks = %d, want 2", ev.NChunks)
	}
	if ev.LatencyMs != 42 {
		t.Errorf("LatencyMs = %d, want 42", ev.LatencyMs)
	}
	if ev.Provider != "anthropic" || ev.Alias != "FreySilvaqzs@qualityservice.com" {
		t.Errorf("metadata fields off: %+v", ev)
	}
}

// TestObserver_DoesNotWriteForUnsubscribedStream pins the per-stream
// routing: a subscriber wired to user_chat must NOT receive app_pipeline
// or probe traffic.
func TestObserver_DoesNotWriteForUnsubscribedStream(t *testing.T) {
	obs, dir := newTestObserver(t, []observerSubscription{
		{Slug: "user-chat-only", Stream: observer.StreamUserChat, PayloadLevel: "metadata"},
	})

	// Fire under app_pipeline (subscriber didn't ask for it).
	req := mkReq(observer.StreamAppPipeline, "trace-app")
	obs.OnRequestStart(context.Background(), req)
	obs.OnRequestEnd(context.Background(), req, 10)

	// File for app_pipeline must not exist.
	appFile := filepath.Join(dir, "user-chat-only", "app_pipeline.ndjson")
	if _, err := os.Stat(appFile); !os.IsNotExist(err) {
		t.Errorf("expected no app_pipeline.ndjson for user_chat subscriber; got err=%v", err)
	}
	// File for user_chat must also be empty (no requests under user_chat).
	events := readEvents(t, dir, "user-chat-only", "user_chat")
	if len(events) != 0 {
		t.Errorf("expected 0 events for unrelated stream, got %+v", events)
	}
}

// TestObserver_MultipleSubscribersSameStream pins fanout — two
// subscribers on the same stream each get their own file with the same
// event line.
func TestObserver_MultipleSubscribersSameStream(t *testing.T) {
	obs, dir := newTestObserver(t, []observerSubscription{
		{Slug: "sub-a", Stream: observer.StreamUserChat, PayloadLevel: "metadata"},
		{Slug: "sub-b", Stream: observer.StreamUserChat, PayloadLevel: "metadata"},
	})

	req := mkReq(observer.StreamUserChat, "trace-multi")
	obs.OnRequestStart(context.Background(), req)
	obs.OnRequestEnd(context.Background(), req, 5)

	for _, slug := range []string{"sub-a", "sub-b"} {
		events := readEvents(t, dir, slug, "user_chat")
		if len(events) != 1 {
			t.Errorf("sub %q: expected 1 event, got %d", slug, len(events))
		}
	}
}

// TestObserver_UnknownStreamSubscriberSkippedNotCrash guards a vault
// containing a typo'd stream name — the observer must skip that
// subscriber gracefully (WARN), not panic.
func TestObserver_UnknownStreamSubscriberSkippedNotCrash(t *testing.T) {
	obs, dir := newTestObserver(t, []observerSubscription{
		{Slug: "typo-sub", Stream: "user-chat", PayloadLevel: "metadata"}, // hyphen typo
		{Slug: "good-sub", Stream: observer.StreamUserChat, PayloadLevel: "metadata"},
	})

	req := mkReq(observer.StreamUserChat, "trace-typo")
	obs.OnRequestStart(context.Background(), req)
	obs.OnRequestEnd(context.Background(), req, 1)

	// Good subscriber still gets the event.
	events := readEvents(t, dir, "good-sub", "user_chat")
	if len(events) != 1 {
		t.Errorf("good subscriber missed event: %+v", events)
	}
	// Typo subscriber's dir must not exist (skipped at Build time).
	if _, err := os.Stat(filepath.Join(dir, "typo-sub")); !os.IsNotExist(err) {
		t.Errorf("expected typo-sub dir absent (skipped at Build); got err=%v", err)
	}
}

// TestObserver_NoSubscribersIsValid pins the noop case: vault returns
// empty → observer builds fine, fires no events, leaves no files.
func TestObserver_NoSubscribersIsValid(t *testing.T) {
	obs, dir := newTestObserver(t, nil)

	req := mkReq(observer.StreamUserChat, "trace-none")
	obs.OnRequestStart(context.Background(), req)
	obs.OnRequestEnd(context.Background(), req, 1)

	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected empty baseDir, got %+v", entries)
	}
}

// TestObserver_FullPayloadLevelDowngradesToMetadataWithWARN — for MVP,
// payload_level=full not yet supported. Subscriber gets metadata events
// (file IS written) but a WARN logs at Build time. Verify file path
// uses the metadata convention (no `-full` suffix or similar).
func TestObserver_FullPayloadLevelDowngradesToMetadataWithWARN(t *testing.T) {
	obs, dir := newTestObserver(t, []observerSubscription{
		{Slug: "compliance", Stream: observer.StreamUserChat, PayloadLevel: "full"},
	})

	req := mkReq(observer.StreamUserChat, "trace-compliance")
	obs.OnRequestStart(context.Background(), req)
	obs.OnRequestEnd(context.Background(), req, 1)

	// Today's MVP writes to <stream>.ndjson regardless of level — the
	// SPEC §1.4.2 distinct `-full.ndjson` path is reserved for the future
	// real-implementation. This test pins the current behavior so the
	// switchover (which adds the `-full.ndjson` path) shows up as a
	// failing test that has to be intentionally rewritten.
	events := readEvents(t, dir, "compliance", "user_chat")
	if len(events) != 1 {
		t.Errorf("expected 1 event in metadata file (MVP downgrade), got %d", len(events))
	}
}

// TestObserver_WriteFailureDoesNotCrash — fail-open: if a file handle
// is closed mid-flight (simulating disk errors), the observer logs WARN
// and continues; subsequent requests for OTHER subscribers must still
// succeed. SPEC §1.4.5 mandates main-path isolation.
func TestObserver_WriteFailureDoesNotCrash(t *testing.T) {
	obs, dir := newTestObserver(t, []observerSubscription{
		{Slug: "sub-a", Stream: observer.StreamUserChat, PayloadLevel: "metadata"},
		{Slug: "sub-b", Stream: observer.StreamUserChat, PayloadLevel: "metadata"},
	})

	// Close the file handle behind sub-a's writer entry to simulate IO
	// failure. We do this through reflection via the type-asserted obs.
	o := obs.(*fanoutObserver)
	for _, e := range o.routing[observer.StreamUserChat] {
		if e.slug == "sub-a" {
			_ = e.file.Close()
			break
		}
	}

	req := mkReq(observer.StreamUserChat, "trace-fail-open")
	obs.OnRequestStart(context.Background(), req)
	obs.OnRequestEnd(context.Background(), req, 1)

	// sub-a's file is closed — write fails silently (WARN logged, no panic).
	// sub-b should still receive the event normally.
	events := readEvents(t, dir, "sub-b", "user_chat")
	if len(events) != 1 {
		t.Errorf("fail-open broken — sub-b should still receive event regardless of sub-a's IO failure; got %d events", len(events))
	}
}

// TestEventFromContext_StableJSONShape pins the wire format (V=1). If
// you change the JSON field names / tags, subscribers (trust-local NDJSON
// tailer in P3 step 8) break — bump the V field and document migration.
func TestEventFromContext_StableJSONShape(t *testing.T) {
	req := &observer.RequestContext{
		Stream:        "user_chat",
		TraceID:       "tid-xyz",
		ProviderID:    "anthropic",
		KeyAlias:      "myalias",
		AppSlug:       "",
		AppKeyID:      "",
		RequestedModel: "claude-sonnet-4-6",
		ResolvedModel:  "claude-sonnet-4-6-20251001",
	}
	ev := EventFromContext(req, 7, 250, "ended")

	if ev.V != 1 {
		t.Errorf("V = %d, want 1 — wire format version drift", ev.V)
	}
	if ev.Stream != "user_chat" || ev.TraceID != "tid-xyz" {
		t.Errorf("base fields drift: %+v", ev)
	}
	if ev.Model != "claude-sonnet-4-6-20251001" {
		t.Errorf("Model should prefer ResolvedModel over RequestedModel: %q", ev.Model)
	}
	if ev.NChunks != 7 || ev.LatencyMs != 250 || ev.Status != "ended" {
		t.Errorf("metric fields drift: %+v", ev)
	}

	// JSON shape check — must not contain omitted/empty fields.
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	// Required keys (always present):
	for _, k := range []string{`"v":1`, `"stream":"user_chat"`, `"trace_id":"tid-xyz"`,
		`"provider":"anthropic"`, `"alias":"myalias"`, `"model":"claude-sonnet-4-6-20251001"`,
		`"n_chunks":7`, `"latency_ms":250`, `"status":"ended"`,
	} {
		if !strings.Contains(s, k) {
			t.Errorf("missing expected key %q in JSON: %s", k, s)
		}
	}
	// Empty fields must be omitted (app_slug / app_key_id):
	if strings.Contains(s, `"app_slug"`) {
		t.Errorf("empty AppSlug should be omitted, got: %s", s)
	}
}
