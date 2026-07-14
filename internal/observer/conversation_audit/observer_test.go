package conversation_audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
	"github.com/AiKeyLabs/pkg/aikeytime"
)

type fakeSink struct{ recs []*ConversationRecord }

func (f *fakeSink) Submit(r *ConversationRecord) { f.recs = append(f.recs, r) }

func newTestObserver(enabled *bool, maxBytes int) (*Observer, *fakeSink) {
	sink := &fakeSink{}
	o := New(Config{
		Sink:     sink,
		Enabled:  func() bool { return *enabled },
		MaxBytes: func() int { return maxBytes },
	})
	return o, sink
}

func anthropicReqBody() []byte {
	return []byte(`{"model":"claude-x","system":"sys","messages":[{"role":"user","content":"hello"}]}`)
}

func driveAnthropicTurn(o *Observer, traceID string, withStop bool) {
	req := &observer.RequestContext{
		ProtocolFamily: protoAnthropic,
		RequestBody:    anthropicReqBody(),
		TraceID:        traceID,
		OrgID:          "org-1",
		OwnerAccountID: "acct-7",
		SeatID:         "seat-3",
		SessionID:      "sess-9",
		ProviderID:     "anthropic",
		StartedAt:      time.Unix(1_700_000_000, 0),
	}
	o.OnRequestStart(context.Background(), req)
	o.OnSSEEvent(context.Background(), req, "content_block_delta", []byte(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi "}}`))
	o.OnSSEEvent(context.Background(), req, "content_block_delta", []byte(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"there"}}`))
	if withStop {
		o.OnSSEEvent(context.Background(), req, "message_stop", []byte(`{"type":"message_stop"}`))
	}
	o.OnRequestEnd(context.Background(), req, 1234)
}

func TestObserver_DisabledCapturesNothing(t *testing.T) {
	enabled := false
	o, sink := newTestObserver(&enabled, 0)
	if o.WantsFullPayload() {
		t.Fatalf("WantsFullPayload=true while disabled")
	}
	driveAnthropicTurn(o, "t1", true)
	if len(sink.recs) != 0 {
		t.Fatalf("submitted %d records while disabled; want 0", len(sink.recs))
	}
}

func TestObserver_HappyPathAssemblesRecord(t *testing.T) {
	enabled := true
	o, sink := newTestObserver(&enabled, 0)
	if !o.WantsFullPayload() {
		t.Fatalf("WantsFullPayload=false while enabled")
	}
	driveAnthropicTurn(o, "trace-abc", true)

	if len(sink.recs) != 1 {
		t.Fatalf("submitted %d records; want 1", len(sink.recs))
	}
	r := sink.recs[0]
	if r.EventID != "trace-abc" {
		t.Fatalf("event_id=%q want trace-abc (stable per-turn key)", r.EventID)
	}
	if r.UserText != "hello" || r.AssistantText != "Hi there" || r.SystemText != "sys" {
		t.Fatalf("texts: user=%q assistant=%q system=%q", r.UserText, r.AssistantText, r.SystemText)
	}
	if r.OrgID != "org-1" || r.OwnerAccountID != "acct-7" || r.SessionID != "sess-9" {
		t.Fatalf("attribution: org=%q owner=%q session=%q", r.OrgID, r.OwnerAccountID, r.SessionID)
	}
	// Seat dimension (2026-07-07): must ride along, or shared-pool-VK turns
	// re-attribute to the VK owner and file under a stranger seat row.
	if r.SeatID != "seat-3" {
		t.Fatalf("seat_id=%q want seat-3", r.SeatID)
	}
	if r.Model != "claude-x" || r.ProviderCode != "anthropic" {
		t.Fatalf("model=%q provider=%q", r.Model, r.ProviderCode)
	}
	if r.RequestStatus != "ok" {
		t.Fatalf("status=%q want ok (saw message_stop)", r.RequestStatus)
	}
	if r.DurationMs == nil || *r.DurationMs != 1234 {
		t.Fatalf("duration_ms=%v want 1234", r.DurationMs)
	}
	if r.ContentBytes == nil || *r.ContentBytes != int64(len("hello")+len("Hi there")+len("sys")) {
		t.Fatalf("content_bytes=%v want sum of field lengths", r.ContentBytes)
	}
	if r.CreatedAt != aikeytime.FromTime(time.Unix(1_700_000_000, 0)) {
		t.Fatalf("created_at=%v want FromTime(start)", r.CreatedAt)
	}
	// State must be cleaned up after the turn.
	if _, ok := o.states.Load("trace-abc"); ok {
		t.Fatalf("turn state not deleted after OnRequestEnd")
	}
}

// TestObserver_CapturesTokenSnapshotFromUsageFrames drives a real Anthropic
// streaming turn whose message_start carries cache tokens (prompt caching) and
// whose message_delta carries output — the observer must fold them into the
// record's display snapshot via the SAME accumulator the usage path uses.
func TestObserver_CapturesTokenSnapshotFromUsageFrames(t *testing.T) {
	enabled := true
	o, sink := newTestObserver(&enabled, 0)
	req := &observer.RequestContext{
		ProtocolFamily: protoAnthropic,
		RequestBody:    anthropicReqBody(),
		TraceID:        "trace-tok",
		OrgID:          "org-1",
		OwnerAccountID: "acct-7",
		SessionID:      "sess-9",
		ProviderID:     "anthropic",
		StartedAt:      time.Unix(1_700_000_000, 0),
	}
	o.OnRequestStart(context.Background(), req)
	o.OnSSEEvent(context.Background(), req, "message_start",
		[]byte(`{"type":"message_start","message":{"model":"claude-x","usage":{"input_tokens":12,"cache_read_input_tokens":340,"cache_creation_input_tokens":56}}}`))
	o.OnSSEEvent(context.Background(), req, "content_block_delta",
		[]byte(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}}`))
	o.OnSSEEvent(context.Background(), req, "message_delta",
		[]byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`))
	o.OnSSEEvent(context.Background(), req, "message_stop", []byte(`{"type":"message_stop"}`))
	o.OnRequestEnd(context.Background(), req, 1234)

	if len(sink.recs) != 1 {
		t.Fatalf("submitted %d records; want 1", len(sink.recs))
	}
	r := sink.recs[0]
	mustI64 := func(name string, p *int64, want int64) {
		t.Helper()
		if p == nil {
			t.Fatalf("%s is NULL; want %d", name, want)
		}
		if *p != want {
			t.Fatalf("%s=%d want %d", name, *p, want)
		}
	}
	mustI64("input_tokens", r.InputTokens, 12)
	mustI64("cached_input_tokens (cache read)", r.CachedInputTokens, 340)
	mustI64("cache_creation_input_tokens", r.CacheCreationInputTokens, 56)
	mustI64("output_tokens", r.OutputTokens, 7)
	// total = pure input + cache read + cache creation + output.
	mustI64("total_tokens", r.TotalTokens, 12+340+56+7)
}

// TestObserver_NoUsageFrameLeavesTokensNull asserts the NULL-not-zero contract:
// a turn with only text deltas (no usage frame — e.g. an interrupted stream)
// leaves every token field NULL, so the drawer can tell "not captured" apart
// from a genuine zero measurement.
func TestObserver_NoUsageFrameLeavesTokensNull(t *testing.T) {
	enabled := true
	o, sink := newTestObserver(&enabled, 0)
	driveAnthropicTurn(o, "trace-nousage", true) // text deltas only, no usage frame
	if len(sink.recs) != 1 {
		t.Fatalf("submitted %d records; want 1", len(sink.recs))
	}
	r := sink.recs[0]
	if r.InputTokens != nil || r.OutputTokens != nil || r.CachedInputTokens != nil ||
		r.CacheCreationInputTokens != nil || r.ReasoningTokens != nil || r.TotalTokens != nil {
		t.Fatalf("tokens must be NULL when no usage frame seen: in=%v out=%v cached=%v cc=%v reason=%v total=%v",
			r.InputTokens, r.OutputTokens, r.CachedInputTokens, r.CacheCreationInputTokens, r.ReasoningTokens, r.TotalTokens)
	}
}

// TestObserver_CacheEnabledFromRequestBody asserts the decision-B caching ON/OFF
// switch: detected from the request body's cache_control directive, 0 when absent.
func TestObserver_CacheEnabledFromRequestBody(t *testing.T) {
	enabled := true

	// No cache_control in the body → off (0), not NULL (a body WAS seen).
	o, sink := newTestObserver(&enabled, 0)
	driveAnthropicTurn(o, "t-nocache", true) // anthropicReqBody() has no cache_control
	if r := sink.recs[0]; r.CacheEnabled == nil || *r.CacheEnabled != 0 {
		t.Fatalf("no cache_control → CacheEnabled want 0, got %v", r.CacheEnabled)
	}

	// cache_control present (Anthropic prompt caching) → on (1).
	o2, sink2 := newTestObserver(&enabled, 0)
	req := &observer.RequestContext{
		ProtocolFamily: protoAnthropic,
		RequestBody:    []byte(`{"model":"claude-x","system":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hi"}]}`),
		TraceID:        "t-cache",
		OrgID:          "org-1",
		OwnerAccountID: "acct-7",
		SessionID:      "sess-9",
		ProviderID:     "anthropic",
		StartedAt:      time.Unix(1_700_000_000, 0),
	}
	o2.OnRequestStart(context.Background(), req)
	o2.OnSSEEvent(context.Background(), req, "content_block_delta",
		[]byte(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}`))
	o2.OnRequestEnd(context.Background(), req, 10)
	if r := sink2.recs[0]; r.CacheEnabled == nil || *r.CacheEnabled != 1 {
		t.Fatalf("cache_control present → CacheEnabled want 1, got %v", r.CacheEnabled)
	}
}

func TestObserver_PartialWhenNoCompletionMarker(t *testing.T) {
	enabled := true
	o, sink := newTestObserver(&enabled, 0)
	driveAnthropicTurn(o, "t-partial", false) // no message_stop
	if len(sink.recs) != 1 {
		t.Fatalf("records=%d want 1", len(sink.recs))
	}
	if sink.recs[0].RequestStatus != "partial" {
		t.Fatalf("status=%q want partial (no completion marker)", sink.recs[0].RequestStatus)
	}
}

func TestObserver_EmptyExtractSkipsRecord(t *testing.T) {
	enabled := true
	o, sink := newTestObserver(&enabled, 0)
	req := &observer.RequestContext{
		ProtocolFamily: protoAnthropic,
		RequestBody:    []byte(`{"model":"claude-x","messages":[]}`), // no user text
		TraceID:        "t-empty",
		StartedAt:      time.Unix(1_700_000_000, 0),
	}
	o.OnRequestStart(context.Background(), req)
	// A non-text control frame only → nothing extracted.
	o.OnSSEEvent(context.Background(), req, "message_start", []byte(`{"type":"message_start"}`))
	o.OnRequestEnd(context.Background(), req, 10)
	if len(sink.recs) != 0 {
		t.Fatalf("submitted %d records with no text; want 0 (skip empty)", len(sink.recs))
	}
}

func TestObserver_CapsTextToMaxBytes(t *testing.T) {
	enabled := true
	o, sink := newTestObserver(&enabled, 4) // cap each field at 4 bytes
	req := &observer.RequestContext{
		ProtocolFamily: protoOpenAI,
		RequestBody:    []byte(`{"model":"gpt-x","messages":[{"role":"user","content":"abcdefgh"}]}`),
		TraceID:        "t-cap",
		StartedAt:      time.Unix(1_700_000_000, 0),
	}
	o.OnRequestStart(context.Background(), req)
	o.OnSSEEvent(context.Background(), req, "", []byte(`{"choices":[{"delta":{"content":"123456"}}]}`))
	o.OnRequestEnd(context.Background(), req, 5)
	if len(sink.recs) != 1 {
		t.Fatalf("records=%d want 1", len(sink.recs))
	}
	r := sink.recs[0]
	if len(r.UserText) > 4 || len(r.AssistantText) > 4 {
		t.Fatalf("uncapped: user=%q(%d) assistant=%q(%d)", r.UserText, len(r.UserText), r.AssistantText, len(r.AssistantText))
	}
	if !strings.HasPrefix("abcdefgh", r.UserText) {
		t.Fatalf("capped user text %q is not a prefix of the original", r.UserText)
	}
}

// TestObserver_SkipsProbeStream: aikey's own connectivity self-tests
// (X-Aikey-Probe → StreamProbe at the NotifyStart boundary) and /probe/<alias>/
// pipeline traffic are NOT employee conversations and must not be recorded —
// mirrors the usage path's `if isAikeyProbe(req) { return }` bypass. Without
// this, every `aikey use`/login connectivity check would add an empty "hi" turn
// that inflates a seat's session/turn counts in the audit.
func TestObserver_SkipsProbeStream(t *testing.T) {
	enabled := true
	o, sink := newTestObserver(&enabled, 0)
	req := &observer.RequestContext{
		ProtocolFamily: protoAnthropic,
		// the literal connectivity probe body: "hi" + max_tokens:1
		RequestBody: []byte(`{"model":"claude-haiku-4-5-20251001","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`),
		TraceID:     "t-probe",
		OrgID:       "org-1",
		ProviderID:  "anthropic",
		Stream:      observer.StreamProbe,
		StartedAt:   time.Unix(1_700_000_000, 0),
	}
	o.OnRequestStart(context.Background(), req)
	o.OnSSEEvent(context.Background(), req, "content_block_delta",
		[]byte(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}`))
	o.OnRequestEnd(context.Background(), req, 10)

	if len(sink.recs) != 0 {
		t.Fatalf("submitted %d records for a probe; want 0 (probes must not be audited)", len(sink.recs))
	}
	if _, ok := o.states.Load("t-probe"); ok {
		t.Fatalf("probe left a dangling turnState; OnRequestStart must not store one for StreamProbe")
	}
}

// TestObserver_RecordsUserChatStream is the contrast guard: a normal
// StreamUserChat turn IS recorded, so the probe skip can't over-match real chat.
func TestObserver_RecordsUserChatStream(t *testing.T) {
	enabled := true
	o, sink := newTestObserver(&enabled, 0)
	req := &observer.RequestContext{
		ProtocolFamily: protoAnthropic,
		RequestBody:    anthropicReqBody(),
		TraceID:        "t-userchat",
		OrgID:          "org-1",
		ProviderID:     "anthropic",
		Stream:         observer.StreamUserChat,
		StartedAt:      time.Unix(1_700_000_000, 0),
	}
	o.OnRequestStart(context.Background(), req)
	o.OnSSEEvent(context.Background(), req, "content_block_delta",
		[]byte(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}}`))
	o.OnSSEEvent(context.Background(), req, "message_stop", []byte(`{"type":"message_stop"}`))
	o.OnRequestEnd(context.Background(), req, 10)
	if len(sink.recs) != 1 {
		t.Fatalf("submitted %d records for user_chat; want 1 (real chat must still record)", len(sink.recs))
	}
}
