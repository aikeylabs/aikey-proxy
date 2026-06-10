package events

import "time"

// UsageEvent records a single proxied request for auditing and analytics.
//
// Phase 4 (AKL-207, 2026-05-20): added 6 fields below the original block
// for the App pipeline audit trail per 主方案 §5.3 主聚合字段. These are
// populated when the request was routed via /apps/<slug>/... — empty for
// legacy /v1/... and /<provider>/v1/... requests, so existing dashboards
// degrade gracefully (NULL on app-only fields).
//
// Deferred to a follow-up: metadata_task / metadata_phase / metadata_subagent
// (need sanitizer-context threading through serveRoute — not blocking for
// Phase 1 because the audit trail's primary use case is "which app made
// the call" which the current 6 fields cover).
type UsageEvent struct {
	ID           int64     `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	VirtualKeyID string    `json:"virtual_key_id"`
	Provider     string    `json:"provider"`
	Model        string    `json:"model"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	DurationMs   int64     `json:"duration_ms"`
	StatusCode   int       `json:"status_code"`
	IsStreaming  bool      `json:"is_streaming"`
	ErrorType    string    `json:"error_type,omitempty"`
	RequestPath  string    `json:"request_path"`

	// App pipeline audit fields (Phase 4, 主方案 §5.3 主聚合).
	// Empty / zero for legacy paths.
	AppSlug          string `json:"app_slug,omitempty"`
	AppKeyID         string `json:"app_key_id,omitempty"`
	AppMode          string `json:"app_mode,omitempty"`          // "isolated" | "follow-active" | ""
	BoundVia         string `json:"bound_via,omitempty"`         // profile_id used at resolve time, e.g., "app:degrade-detector" or "default"
	RequestedModel   string `json:"requested_model,omitempty"`   // body's `model` field (may differ from resolved if translator remaps)
	ResolvedProvider string `json:"resolved_provider,omitempty"` // post-binding provider_code (Anthropic / openai / kimi_code)

	// SessionID — per-conversation session ID extracted from the
	// inbound request via sessionid/session-fingerprint.yaml (Claude Code
	// header / Kimi prompt_cache_key / OpenAI conversation_id /
	// X-Aikey-Session-Id convention). Persisted to local events.db
	// so the offline-retry upload path preserves the dimension if
	// the proxy reports drained from cache. Wire serialization on
	// ReportableEvent uses the same json:"session_id" tag for parity.
	SessionID string `json:"session_id,omitempty"`

	// Trace correlation — request-scoped W3C trace identifiers captured at the
	// HTTP entry (observability.ExtractOrCreate) and threaded here purely so the
	// async collector can cite them when it has to drop a billing event under
	// backpressure (logging-conventions: WARN/ERROR must carry trace_id /
	// span_id / request_id). json:"-" because these are ephemeral log
	// correlation, NOT a persisted/wire dimension — Insert() uses an explicit
	// column list and ReportableEvent its own tags, so adding these does not
	// touch the events.db schema or the upload contract.
	TraceID   string `json:"-"`
	SpanID    string `json:"-"`
	RequestID string `json:"-"`
}
