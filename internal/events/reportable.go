package events

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/aikeytime"
)

// ReportableEvent contains all anchor fields required by collector-service.
// Built from request context after response completion.
type ReportableEvent struct {
	// identifiers
	EventID         string    `json:"event_id"`
	RequestID       string    `json:"request_id,omitempty"`
	TraceID         string    `json:"trace_id,omitempty"`
	ProxyInstanceID string    `json:"proxy_instance_id,omitempty"`
	DeviceID        string    `json:"device_id,omitempty"`
	// UpstreamRequestID carries the provider's own request id (e.g. anthropic's
	// `req_011CaQVp...` / openai's `req_xxx` / kimi's `cid-xxx`). Captured from
	// response headers when present so support can correlate a 4xx/5xx in our
	// ODS with the provider's audit log without us having to log full bodies.
	// Always populated for both success + error paths when upstream sets it.
	UpstreamRequestID string `json:"upstream_request_id,omitempty"`

	// schema + source metadata
	SchemaVersion      int    `json:"schema_version"`
	SourceVersion      string `json:"source_version,omitempty"`
	ClientVersion      string `json:"client_version,omitempty"`
	ProxyConfigVersion string `json:"proxy_config_version,omitempty"`
	ProxyLoadedControlSeq *int64 `json:"proxy_loaded_control_seq,omitempty"`

	// timestamps: int64 Unix epoch milliseconds (UTC). Wire format switched
	// from RFC3339 strings in v1.0.3-alpha — see the design doc at
	// roadmap20260320/技术实现/update/20260424-时间戳统一为int64毫秒-data-service.md.
	// Why: SQLite storage of time.Time via Go's default String format
	// broke strftime-based hour bucketing on the query side.
	EventTime  aikeytime.Millis  `json:"event_time"`
	OccurredAt aikeytime.Millis  `json:"occurred_at"`
	StartedAt  *aikeytime.Millis `json:"started_at,omitempty"`
	FinishedAt *aikeytime.Millis `json:"finished_at,omitempty"`

	// ownership (D3 naming)
	OrgID     string `json:"org_id"`
	AccountID string `json:"account_id,omitempty"`
	SeatID    string `json:"seat_id,omitempty"`

	// routing — audit anchor fields
	VirtualKeyID               string `json:"virtual_key_id,omitempty"`
	VirtualKeyRevision         string `json:"virtual_key_revision,omitempty"`
	VirtualKeyHash             string `json:"virtual_key_hash,omitempty"`     // SHA-256 of bearer token (not just ID)
	BindingID                  string `json:"binding_id,omitempty"`           // from local cache if available
	CredentialID               string `json:"credential_id,omitempty"`
	CredentialRevision         string `json:"credential_revision,omitempty"`
	RealKeyHash                string `json:"real_key_hash,omitempty"`        // SHA-256 of decrypted provider key
	CredentialFingerprint      string `json:"credential_fingerprint,omitempty"` // SHA-256 of credential_id+revision
	ProviderAccountFingerprint string `json:"provider_account_fingerprint,omitempty"`
	OAuthIdentity              string `json:"oauth_identity,omitempty"` // Email/display name for OAuth accounts (personal)

	// provider / protocol
	ProviderID   string `json:"provider_id,omitempty"`
	ProviderCode string `json:"provider_code,omitempty"`
	ProtocolType string `json:"protocol_type,omitempty"`
	RouteSource  string `json:"route_source,omitempty"`

	// usage
	Model        string `json:"model,omitempty"`
	RequestCount int    `json:"request_count"`
	InputTokens  *int64 `json:"input_tokens,omitempty"`
	OutputTokens *int64 `json:"output_tokens,omitempty"`
	TotalTokens  *int64 `json:"total_tokens,omitempty"`

	// Cache-aware input breakdown. Populated by Anthropic; zero (and omitted)
	// for providers that don't expose prompt caching. InputTokens remains the
	// authoritative total — these are diagnostic splits for UI rendering and
	// (later) cost estimation. Adding as new fields keeps pre-v5 consumers
	// parsing correctly via json:",omitempty".
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens,omitempty"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens,omitempty"`

	// StopReason is the raw provider-specific termination reason (Anthropic
	// `stop_reason` or OpenAI/Kimi `choices[0].finish_reason`), passed
	// through un-normalized. Used by UI to hint at "max_tokens"/"length"
	// truncation; also reserved as a fallback turn-boundary signal for
	// clients without a Stop hook (see 费用小票-Kimi集成方案 §0.2).
	StopReason string `json:"stop_reason,omitempty"`

	// result
	RequestStatus  string `json:"request_status"`
	HTTPStatusCode *int   `json:"http_status_code,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
	ErrorMessage   string `json:"error_message,omitempty"`

	// UI anchor fields (费用小票/仪表盘).  omitempty so downstream consumers
	// expecting the pre-v5 schema continue to parse.
	//
	// SessionID: X-Claude-Code-Session-Id header value.  Populated only for
	//   Claude Code originated requests; empty for Kimi CLI / curl / others.
	// KeyLabel:  user-friendly name for the underlying credential derived
	//   from RouteSource (OAuth email / team or personal alias / id prefix).
	//   Lets CLI consumers render a receipt without vault lookups.
	// Completion: transport-level completion state.  "complete" is the happy
	//   path; "partial" means the client disconnected mid-stream and we
	//   recorded whatever tokens arrived; "interrupted" is an upstream error.
	SessionID  string `json:"session_id,omitempty"`
	KeyLabel   string `json:"key_label,omitempty"`
	Completion string `json:"completion,omitempty"`
}

// ReportOpts collects all context needed to build a ReportableEvent.
type ReportOpts struct {
	EventID         string
	ProxyInstanceID string
	Route           *vkeys.ResolvedRoute
	BearerToken     string // the full "aikey_vk_..." token from the request
	Model           string
	StartTime       time.Time
	FinishedAt      time.Time
	StatusCode      int
	InputTokens     int
	OutputTokens    int
	// Optional cache breakdown. Leave zero for providers without caching;
	// BuildReportableEvent will omit these fields from the JSON event.
	CacheReadInputTokens     int
	CacheCreationInputTokens int
	// StopReason is the raw termination string from the provider; pass
	// through un-normalized. BuildReportableEvent omits the JSON field
	// when empty.
	StopReason string
	ErrorType       string
	RealKey         string // decrypted provider key (for hashing only, never stored)
	SourceVersion      string
	ClientVersion      string
	ProxyConfigVersion string
	LoadedControlSeq   int64
	LoggedInAccountID  string // fallback account_id for personal keys

	// UI anchor fields (see ReportableEvent docs for semantics).
	// SessionID comes from the X-Claude-Code-Session-Id request header.
	// Completion defaults to "complete" if left empty.
	SessionID  string
	Completion string

	// UpstreamRequestID is the provider's own request id from response headers
	// (anthropic: `request-id`, openai/kimi: `x-request-id` or
	// `openai-request-id`). Carried through so support can pivot from a local
	// ODS row to provider-side logs.
	UpstreamRequestID string
}

// BuildReportableEvent creates a ReportableEvent from the proxy request context.
func BuildReportableEvent(opts ReportOpts) ReportableEvent {
	route := opts.Route
	now := opts.FinishedAt
	nowMs := aikeytime.FromTime(now)
	startMs := aikeytime.FromTime(opts.StartTime)

	var inTok, outTok, totalTok int64
	inTok = int64(opts.InputTokens)
	outTok = int64(opts.OutputTokens)
	totalTok = inTok + outTok

	status := "success"
	if opts.StatusCode >= 400 {
		status = "error"
	}

	// Prefer the route-carried RouteSource (set at registry construction time)
	// for authoritative classification.  Fall back to OrgID-based inference
	// only when the legacy caller hasn't populated it yet, to stay compatible
	// with older data paths until the cutover is complete.
	routeSource := route.RouteSource
	orgID := route.OrgID
	if routeSource == "" {
		if orgID != "" {
			routeSource = "team_managed"
		} else {
			routeSource = "personal"
		}
	}
	if orgID == "" {
		// Personal keys have no org — use "personal" as a sentinel so the
		// event passes ingest validation (org_id is required).
		orgID = "personal"
	}

	// virtual_key_hash: hash the bearer token, not just the ID.
	// The bearer token is a secret that only the legitimate key holder possesses,
	// so its hash serves as a non-forgeable audit anchor.
	vkHash := hashIfNotEmpty(opts.BearerToken)

	// credential_fingerprint: hash of credential_id + revision for cross-reference
	credFP := ""
	if route.CredentialID != "" {
		credFP = hashIfNotEmpty(route.CredentialID + ":" + route.CredentialRevision)
	}

	ev := ReportableEvent{
		EventID:           opts.EventID,
		UpstreamRequestID: opts.UpstreamRequestID,
		ProxyInstanceID:   opts.ProxyInstanceID,
		SchemaVersion:     1,
		SourceVersion:      opts.SourceVersion,
		ClientVersion:      opts.ClientVersion,
		ProxyConfigVersion: opts.ProxyConfigVersion,
		ProxyLoadedControlSeq: func() *int64 {
			if opts.LoadedControlSeq == 0 {
				return nil
			}
			v := opts.LoadedControlSeq
			return &v
		}(),

		EventTime:  nowMs,
		OccurredAt: nowMs,
		StartedAt:  &startMs,
		FinishedAt: &nowMs,

		OrgID: orgID,
		AccountID: func() string {
			if route.AccountID != "" {
				return route.AccountID
			}
			return opts.LoggedInAccountID // fallback for personal keys
		}(),
		SeatID: route.SeatID,

		VirtualKeyID:          route.VirtualKeyID,
		VirtualKeyRevision:    route.VirtualKeyRevision,
		VirtualKeyHash:        vkHash,
		BindingID:             route.BindingID,
		CredentialID:          route.CredentialID,
		CredentialRevision:    route.CredentialRevision,
		RealKeyHash:           hashIfNotEmpty(opts.RealKey),
		CredentialFingerprint: credFP,

		ProviderID:    route.ProviderID,
		ProviderCode:  route.ProviderCode,
		ProtocolType:  route.ProtocolType,
		RouteSource:   routeSource,
		OAuthIdentity: route.OAuthIdentity,

		Model:        opts.Model,
		RequestCount: 1,
		InputTokens:  &inTok,
		OutputTokens: &outTok,
		TotalTokens:  &totalTok,
		// Only surface cache pointers when the upstream actually returned
		// nonzero values. Keeping them nil for OpenAI/Kimi ensures omitempty
		// drops the keys from the JSON, which matches the pre-v5 event shape
		// consumers still parse today.
		CacheReadInputTokens:     int64PtrIfNonZero(opts.CacheReadInputTokens),
		CacheCreationInputTokens: int64PtrIfNonZero(opts.CacheCreationInputTokens),

		StopReason: opts.StopReason,

		RequestStatus:  status,
		HTTPStatusCode: &opts.StatusCode,
		ErrorCode:      opts.ErrorType,

		SessionID:  opts.SessionID,
		KeyLabel:   deriveKeyLabel(route),
		Completion: completionOrDefault(opts.Completion),
	}
	return ev
}

// deriveKeyLabel returns a user-facing identifier for the credential based on
// its route_source classification.  For OAuth accounts the display_identity
// (email or session id) is most meaningful; for team / personal keys the
// alias is what the user sees in `aikey list`; otherwise we truncate the
// virtual_key_id as a last resort so the UI always has something to render.
func deriveKeyLabel(route *vkeys.ResolvedRoute) string {
	if route == nil {
		return ""
	}
	switch route.RouteSource {
	case "oauth":
		if route.OAuthIdentity != "" {
			return route.OAuthIdentity
		}
	case "team", "personal", "personal_byok":
		if route.KeyAlias != "" && route.KeyAlias != "__oauth__" {
			return route.KeyAlias
		}
	}
	// Fallback: first 12 chars of virtual_key_id.  Stable enough to identify
	// the row in the WAL even when more specific labels are unavailable.
	if vk := route.VirtualKeyID; vk != "" {
		if len(vk) > 12 {
			return vk[:12]
		}
		return vk
	}
	return ""
}

// completionOrDefault normalizes the transport completion state.  "complete"
// is assumed when the caller hasn't set anything explicitly; the stream
// drainer fills in "partial" / "interrupted" when it detects those cases.
func completionOrDefault(c string) string {
	switch c {
	case "complete", "partial", "interrupted":
		return c
	default:
		return "complete"
	}
}

// int64PtrIfNonZero returns a pointer to the int64 value when non-zero, or nil.
// Used to let json:",omitempty" drop optional counters (cache splits) from the
// event when the provider didn't populate them.
func int64PtrIfNonZero(n int) *int64 {
	if n == 0 {
		return nil
	}
	v := int64(n)
	return &v
}

// hashIfNotEmpty returns a SHA-256 hex digest, or empty string.
func hashIfNotEmpty(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
