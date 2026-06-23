package conversation_audit

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
	"github.com/AiKeyLabs/pkg/aikeytime"
)

// ConversationRecord mirrors the collector's
// conversation.ConversationRecord wire shape (aikey-data). The proxy and
// collector share the JSON contract, NOT Go types (they are separate modules) —
// so this is a deliberate byte-for-byte mirror, the same pattern content_reporter
// and ndjson_fanout use. Keep the json tags in lockstep with the collector's
// domain.go; the cross-service contract is the JSON, and a drift here is a
// silent ingest bug.
//
// Tokens are a per-turn DISPLAY snapshot (the audit thread drawer shows them);
// usage_events stays the billing authority. The observer folds them from the
// SAME SSE frames it reads for assistant text, via a provider.StreamAccumulator
// (single source of truth with the usage path — no re-implemented parsing). A
// rare trailing partial frame the framework withholds from observers may
// undercount by one frame; acceptable for display, never used for billing. All
// token columns are nullable (left NULL when no usage frame was seen, e.g. a
// partial/interrupted stream). source_id / source_seq are stamped by the
// RecordSink, not the observer.
type ConversationRecord struct {
	// Token snapshot (display only). Pointers so an absent field is NULL, not 0
	// — kept NULL when no usage frame arrived. Names/tags mirror the collector's
	// conversation.ConversationRecord (cached_input_tokens = cache READ, matching
	// the usage column naming; TokenBreakdown calls the same field CacheRead).
	InputTokens  *int64 `json:"input_tokens,omitempty"`
	ContentBytes *int64 `json:"content_bytes,omitempty"`
	DurationMs   *int64 `json:"duration_ms,omitempty"`
	// CacheEnabled (decision B): did the client REQUEST prompt caching this turn
	// (request body carried a cache_control directive)? 1=on, 0=off, nil=couldn't
	// tell (request body not buffered). Distinct from the cache COUNTS above, which
	// read 0 both when caching was off AND when it was requested but ineffective —
	// so the audit drawer can show an explicit caching ON/OFF switch.
	CacheEnabled             *int64           `json:"cache_enabled,omitempty"`
	TotalTokens              *int64           `json:"total_tokens,omitempty"`
	ReasoningTokens          *int64           `json:"reasoning_tokens,omitempty"`
	SourceSeq                *int64           `json:"source_seq,omitempty"`
	CacheCreationInputTokens *int64           `json:"cache_creation_input_tokens,omitempty"`
	CachedInputTokens        *int64           `json:"cached_input_tokens,omitempty"`
	OutputTokens             *int64           `json:"output_tokens,omitempty"`
	SourceID                 string           `json:"source_id,omitempty"`
	SystemText               string           `json:"system_text,omitempty"`
	AssistantText            string           `json:"assistant_text,omitempty"`
	UserText                 string           `json:"user_text,omitempty"`
	ProviderCode             string           `json:"provider_code,omitempty"`
	Model                    string           `json:"model,omitempty"`
	EventID                  string           `json:"event_id"`
	VirtualKeyID             string           `json:"virtual_key_id,omitempty"`
	OwnerAccountID           string           `json:"owner_account_id"`
	SessionID                string           `json:"session_id"`
	RequestStatus            string           `json:"request_status"`
	OrgID                    string           `json:"org_id"`
	CreatedAt                aikeytime.Millis `json:"created_at"`
}

// RecordSink is the durable outbox the observer hands assembled records to. The
// sink owns delivery mechanics (source-seq allocation, content-WAL append,
// waking the uploader) so the observer stays decoupled from events.ContentWAL /
// SeqAllocator / ContentReporter. Submit must be non-blocking and panic-free
// relative to the caller — it runs on the observer's per-request goroutine.
type RecordSink interface {
	Submit(rec *ConversationRecord)
}

// Config wires the observer to its sink + live policy. Enabled / MaxBytes are
// funcs (not values) because the org policy flips at runtime via the 60s policy
// poll — the observer must read the live value, never a snapshot.
type Config struct {
	Sink     RecordSink
	Enabled  func() bool // live conversation_audit_enabled for this tenant
	MaxBytes func() int  // live per-field content cap (content_max_bytes)
	Logger   *slog.Logger
}

// Observer is the conversation-audit StreamingObserver. It captures the prompt
// (from the request body the framework exposes when WantsFullPayload) in
// OnRequestStart, accumulates the assistant completion across OnSSEEvent frames,
// and submits one ConversationRecord per turn in OnRequestEnd.
//
// Fault isolation: every hook early-returns when audit is disabled or state is
// missing, and capture failures degrade silently to a smaller/absent record —
// a stalled audit must never affect the proxied request (the framework already
// runs each hook on an isolated, panic-limited goroutine).
type Observer struct {
	cfg    Config
	logger *slog.Logger
	states sync.Map // traceID(string) → *turnState
}

// turnState is the per-request accumulator. The framework calls this observer's
// three hooks serially on one per-request goroutine, so a single request's state
// needs no internal lock; only the cross-request `states` map is synchronized.
type turnState struct {
	// tokenAcc folds the per-turn token snapshot from the SSE frames as they
	// arrive (same frames fed to assistant text). nil for families without an
	// incremental extractor (e.g. gemini) — those turns capture no tokens.
	tokenAcc provider.StreamAccumulator
	// cacheEnabled (decision B): whether this turn's request asked for prompt
	// caching (detected from the request body in OnRequestStart). nil = no body.
	cacheEnabled *int64
	userText     string
	systemText   string
	model        string
	assistant    strings.Builder
	sawDone      bool
	sawFrame     bool
}

// New builds the observer. Returns a typed *Observer (registration.go adapts it
// to the framework's StreamingObserver via Build).
func New(cfg Config) *Observer {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default().With("component", "conversation-audit")
	}
	if cfg.MaxBytes == nil {
		cfg.MaxBytes = func() int { return 262144 } // 256 KiB default, mirrors schema
	}
	return &Observer{cfg: cfg, logger: cfg.Logger}
}

// WantsFullPayload implements observer.FullPayloadObserver — the proxy buffers
// the request body only while audit is enabled for this proxy's tenant.
func (o *Observer) WantsFullPayload() bool {
	return o.cfg.Enabled != nil && o.cfg.Enabled()
}

func (o *Observer) enabled() bool { return o.cfg.Enabled != nil && o.cfg.Enabled() }

// OnRequestStart extracts the prompt + model from the buffered request body.
func (o *Observer) OnRequestStart(_ context.Context, req *observer.RequestContext) {
	if !o.enabled() || req == nil {
		return
	}
	// Skip probe traffic. aikey's own connectivity self-tests (X-Aikey-Probe,
	// mapped to StreamProbe at the NotifyStart boundary) and /probe/<alias>/
	// pipeline traffic are not employee conversations — recording them adds an
	// empty "hi" turn that inflates a seat's session/turn counts. Mirrors the
	// usage path's `if isAikeyProbe(req) { return }` bypass. No turnState is
	// stored, so the matching OnSSEEvent / OnRequestEnd no-op on the TraceID.
	if req.Stream == observer.StreamProbe {
		return
	}
	st := &turnState{tokenAcc: provider.NewStreamAccumulatorForFamily(req.ProtocolFamily)}
	st.cacheEnabled = detectCacheEnabled(req.RequestBody)
	if len(req.RequestBody) > 0 {
		// Parse-once: prompt + system + model from a single Unmarshal (see
		// extractPrompt) — never re-parse the body for model separately.
		st.userText, st.systemText, st.model = extractPrompt(req.ProtocolFamily, req.RequestBody)
	}
	o.states.Store(req.TraceID, st)
}

// OnSSEEvent accumulates assistant text from each upstream frame.
func (o *Observer) OnSSEEvent(_ context.Context, req *observer.RequestContext, eventType string, payload []byte) {
	if !o.enabled() || req == nil {
		return
	}
	v, ok := o.states.Load(req.TraceID)
	if !ok {
		return
	}
	st, _ := v.(*turnState)
	st.sawFrame = true
	// Fold the per-turn token snapshot from the same frame (the accumulator
	// ignores non-usage frames). Same goroutine as text accumulation, so no lock.
	if st.tokenAcc != nil {
		st.tokenAcc.Feed(payload)
	}
	if delta := extractAssistantDelta(req.ProtocolFamily, eventType, payload); delta != "" {
		st.assistant.WriteString(delta)
	}
	if isCompletionMarker(req.ProtocolFamily, eventType, payload) {
		st.sawDone = true
	}
}

// OnRequestEnd assembles + submits the record, then drops the per-request state.
func (o *Observer) OnRequestEnd(_ context.Context, req *observer.RequestContext, totalLatencyMs int) {
	if req == nil {
		return
	}
	v, ok := o.states.LoadAndDelete(req.TraceID)
	if !ok || !o.enabled() {
		return
	}
	st, _ := v.(*turnState)

	maxB := o.cfg.MaxBytes()
	userText := capText(st.userText, maxB)
	assistantText := capText(st.assistant.String(), maxB)
	systemText := capText(st.systemText, maxB)

	// Nothing conversational captured: skip the empty row, but WARN when frames
	// did arrive — that means the protocol extractor missed text (a parse gap to
	// investigate), not a genuinely empty turn.
	if userText == "" && assistantText == "" {
		if st.sawFrame {
			o.logger.Warn("conversation audit: frames seen but no text extracted; skipping record",
				"event.name", "conversation.capture.empty_extract",
				"error.code", "CONTENT_EMPTY_EXTRACT",
				"protocol_family", req.ProtocolFamily, "trace_id", req.TraceID)
		}
		return
	}

	model := st.model
	if model == "" {
		model = firstNonEmpty(req.ResolvedModel, req.RequestedModel)
	}
	status := "ok"
	if !st.sawDone {
		status = "partial"
	}
	latency := int64(totalLatencyMs)
	bytesTotal := int64(len(userText) + len(assistantText) + len(systemText))

	rec := &ConversationRecord{
		EventID:        req.TraceID, // stable per-turn idempotency key
		OrgID:          orgOrPersonal(req.OrgID),
		SessionID:      req.SessionID,
		OwnerAccountID: req.OwnerAccountID,
		Model:          model,
		ProviderCode:   req.ProviderID,
		UserText:       userText,
		AssistantText:  assistantText,
		SystemText:     systemText,
		DurationMs:     &latency,
		RequestStatus:  status,
		ContentBytes:   &bytesTotal,
		CreatedAt:      aikeytime.FromTime(req.StartedAt),
	}
	if st.tokenAcc != nil {
		stampTokens(rec, st.tokenAcc.Result())
	}
	rec.CacheEnabled = st.cacheEnabled
	if o.cfg.Sink != nil {
		o.cfg.Sink.Submit(rec)
	}
}

// detectCacheEnabled reports whether the request asked for prompt caching this
// turn, from the buffered request body: 1 when it carries a `cache_control`
// directive (Anthropic prompt-caching — the only provider with a client-side
// caching opt-in; OpenAI/Gemini caching is automatic so their bodies never carry
// it and correctly read 0), 0 when a body was seen without it, nil when no body
// was buffered (can't tell). A byte-substring check on the JSON key is enough —
// no full re-parse — and is the request-side analog of the per-turn token
// snapshot. Decision B (2026-06-17).
func detectCacheEnabled(body []byte) *int64 {
	if len(body) == 0 {
		return nil // body not buffered → unknown (kept NULL, not a false "off")
	}
	var v int64
	if bytes.Contains(body, []byte(`"cache_control"`)) {
		v = 1
	}
	return &v
}

// stampTokens copies the accumulated breakdown onto the record as a per-turn
// DISPLAY snapshot. It is a no-op (record fields stay NULL) when no usage frame
// was seen — a fully-zeroed breakdown means "not captured" (partial/interrupted
// stream that never reached the usage frame), NOT "0 tokens", so we don't write
// misleading zeros that the drawer can't distinguish from a real measurement.
// TotalTokens = all input buckets + output (reasoning is already folded into
// output for the providers that surface it separately, so it is not re-added).
func stampTokens(rec *ConversationRecord, br provider.TokenBreakdown) {
	if br.InputTokens == 0 && br.OutputTokens == 0 &&
		br.CacheReadInputTokens == 0 && br.CacheCreationInputTokens == 0 {
		return
	}
	in := int64(br.InputTokens)
	out := int64(br.OutputTokens)
	cr := int64(br.CacheReadInputTokens)
	cc := int64(br.CacheCreationInputTokens)
	re := int64(br.ReasoningTokens)
	total := in + cr + cc + out
	rec.InputTokens = &in
	rec.OutputTokens = &out
	rec.CachedInputTokens = &cr
	rec.CacheCreationInputTokens = &cc
	rec.ReasoningTokens = &re
	rec.TotalTokens = &total
}

// capText truncates s to at most max bytes on a UTF-8 rune boundary (never
// splits a multi-byte rune, which would corrupt display). max<=0 → no cap.
func capText(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// orgOrPersonal mirrors the usage path's required-org sentinel so a personal
// (non-org) request still passes collector ingest validation.
func orgOrPersonal(org string) string {
	if org == "" {
		return "personal"
	}
	return org
}
