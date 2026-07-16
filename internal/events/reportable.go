package events

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/aikeytime"
	"github.com/AiKeyLabs/pkg/usagehash"
)

// ReportableEvent contains all anchor fields required by collector-service.
// Built from request context after response completion.
type ReportableEvent struct {
	ProxyLoadedControlSeq *int64  `json:"proxy_loaded_control_seq,omitempty"`
	HTTPStatusCode        *int    `json:"http_status_code,omitempty"`
	EndpointURL           *string `json:"endpoint_url,omitempty"`
	Region                *string `json:"region,omitempty"`
	// Cost-pricing audit (v1.0.0-rc.8): reasoning tokens (o-series) + upstream
	// region/endpoint. omitempty keeps them off the wire for events lacking them.
	ReasoningTokens          *int64 `json:"reasoning_tokens,omitempty"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens,omitempty"`
	// Cache-aware input breakdown. Populated by Anthropic; zero (and omitted)
	// for providers that don't expose prompt caching. InputTokens remains the
	// authoritative total — these are diagnostic splits for UI rendering and
	// (later) cost estimation. Adding as new fields keeps pre-v5 consumers
	// parsing correctly via json:",omitempty".
	//
	// Wire-format note (2026-04-29): JSON tags follow Anthropic's nomenclature
	// (`cache_read_input_tokens` / `cache_creation_input_tokens`). Two
	// downstream consumers parse this struct:
	//   1. CLI WAL reader (aikey-cli/src/usage_wal.rs) — Rust struct
	//      uses the same field names → must stay Anthropic-faithful.
	//   2. Collector ingest (aikey-data/collector-service/internal/ingest)
	//      — its Go struct's JSON tags were re-aligned to
	//      `cache_read_input_tokens` (matching this) on 2026-04-29 to
	//      fix a long-standing field-name mismatch that silently dropped
	//      cache_read values on the wire (DB column `cached_input_tokens`
	//      is the legacy storage name; collector struct tag now bridges
	//      the two). See bugfix 2026-04-29-cached-tokens-wire-mismatch.md.
	CacheReadInputTokens  *int64            `json:"cache_read_input_tokens,omitempty"`
	SourceSeq             *int64            `json:"source_seq,omitempty"`
	TotalTokens           *int64            `json:"total_tokens,omitempty"`
	OutputTokens          *int64            `json:"output_tokens,omitempty"`
	InputTokens           *int64            `json:"input_tokens,omitempty"`
	FinishedAt            *aikeytime.Millis `json:"finished_at,omitempty"`
	StartedAt             *aikeytime.Millis `json:"started_at,omitempty"`
	CredentialFingerprint string            `json:"credential_fingerprint,omitempty"` // SHA-256 of credential_id+revision
	RequestID             string            `json:"request_id,omitempty"`
	ResolvedProvider      string            `json:"resolved_provider,omitempty"` // post-binding provider_code (anthropic / openai / kimi_code / ...)
	ProxyConfigVersion    string            `json:"proxy_config_version,omitempty"`
	ClientVersion         string            `json:"client_version,omitempty"`
	// ownership (D3 naming)
	OrgID     string `json:"org_id"`
	AccountID string `json:"account_id,omitempty"`
	SeatID    string `json:"seat_id,omitempty"`
	// routing — audit anchor fields
	VirtualKeyID       string `json:"virtual_key_id,omitempty"`
	VirtualKeyRevision string `json:"virtual_key_revision,omitempty"`
	VirtualKeyHash     string `json:"virtual_key_hash,omitempty"` // SHA-256 of bearer token (not just ID)
	BindingID          string `json:"binding_id,omitempty"`       // from local cache if available
	CredentialID       string `json:"credential_id,omitempty"`
	CredentialRevision string `json:"credential_revision,omitempty"`
	RealKeyHash        string `json:"real_key_hash,omitempty"` // SHA-256 of decrypted provider key
	// identifiers
	EventID                    string `json:"event_id"`
	ProviderAccountFingerprint string `json:"provider_account_fingerprint,omitempty"`
	OAuthIdentity              string `json:"oauth_identity,omitempty"` // Email/display name for OAuth accounts (personal)
	// provider / protocol
	ProviderID   string `json:"provider_id,omitempty"`
	ProviderCode string `json:"provider_code,omitempty"`
	ProtocolType string `json:"protocol_type,omitempty"`
	RouteSource  string `json:"route_source,omitempty"`
	// usage
	Model          string `json:"model,omitempty"`
	RequestedModel string `json:"requested_model,omitempty"` // body.model captured at request entry
	SourceVersion  string `json:"source_version,omitempty"`
	BoundVia       string `json:"bound_via,omitempty"` // "app:<slug>" (isolated) | "default" (follow-active)
	// ContentHash is the financial-grade tamper/corruption fingerprint over the
	// metering tuple (pkg/usagehash, stage C). The collector RECOMPUTES it and
	// compares; a mismatch quarantines the event instead of billing a silently
	// corrupted value (e.g. a token count that became 0 in transit). Empty on
	// events built before stage C / by older proxies — the collector then skips
	// validation (conserve, never false-quarantine). Carried on the wire so the
	// collector receives the client-stamped value alongside the fields it hashes.
	ContentHash string `json:"content_hash,omitempty"`
	// Delivery integrity (2026-05-30). SourceID is this vault's stable source
	// identity (runtime.source_identity — a vault-scoped install id, NOT a
	// hardware fingerprint). SourceSeq is its per-source, never-reused sequence
	// from SeqAllocator; the collector uses (SourceID, SourceSeq) to detect gaps
	// and prove completeness. Dedicated fields (not overloaded onto DeviceID) so
	// the wire contract is explicit and matches the server's
	// usage_event_ods.source_id/source_seq columns. Empty/nil on legacy events —
	// those store fine but skip gap detection. SourceSeq is a pointer so
	// "absent" (v1) is distinguishable from a real 0.
	SourceID string `json:"source_id,omitempty"`
	// UpstreamRequestID carries the provider's own request id (e.g. anthropic's
	// `req_011CaQVp...` / openai's `req_xxx` / kimi's `cid-xxx`). Captured from
	// response headers when present so support can correlate a 4xx/5xx in our
	// ODS with the provider's audit log without us having to log full bodies.
	// Always populated for both success + error paths when upstream sets it.
	UpstreamRequestID string `json:"upstream_request_id,omitempty"`
	// RequestPath is the inbound request's URL path (e.g. "/v1/messages",
	// "/openai/v1/models"). 2026-07-15 非生成流量不进用量审计: the projector
	// classifies generation vs non-generation traffic (GET /v1/models health
	// polls etc.) from this FACT — the proxy deliberately reports the path,
	// not a verdict, so classification policy lives in ONE place (the
	// enricher's generation-endpoint table). Additive + omitempty: legacy
	// consumers (CLI WAL serde, older collectors) ignore it; events from
	// older proxies simply lack it and keep their current classification.
	RequestPath string `json:"request_path,omitempty"`
	DeviceID          string `json:"device_id,omitempty"`
	ProxyInstanceID   string `json:"proxy_instance_id,omitempty"`
	TraceID           string `json:"trace_id,omitempty"`
	// StopReason is the raw provider-specific termination reason (Anthropic
	// `stop_reason` or OpenAI/Kimi `choices[0].finish_reason`), passed
	// through un-normalized. Used by UI to hint at "max_tokens"/"length"
	// truncation; also reserved as a fallback turn-boundary signal for
	// clients without a Stop hook (see 费用小票-Kimi集成方案 §0.2).
	StopReason string `json:"stop_reason,omitempty"`
	// result
	RequestStatus string `json:"request_status"`
	AppMode       string `json:"app_mode,omitempty"` // "isolated" | "follow-active"
	ErrorCode     string `json:"error_code,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
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
	// Phase 4 App pipeline attribution fields (主方案 §5.3).
	//
	// Populated only when RouteSource == "app" (i.e. request flowed through
	// /apps/<slug>/v1/...). Empty / omitted on JSON wire for legacy
	// /v1/... and /<provider>/v1/... requests so existing collector / WAL
	// consumers continue to parse the pre-Phase-4 shape.
	//
	// Mirrors the same 6 fields on UsageEvent (the local SQLite shape) so
	// audit trail attribution is identical across the two pipelines:
	//   UsageEvent → SQLite usage_events table (statusline / aikey app list)
	//   ReportableEvent → WAL + collector (centralized billing / dashboard)
	//
	// AKL-207 §5.3 close-out (2026-05-21): the UsageEvent side was wired
	// in 2026-05-20 but ReportableEvent shape was left unattributed —
	// degrade-detector traffic would have shown up in the collector with
	// app_slug = "" had M2 launched today. This block closes that gap.
	AppSlug  string `json:"app_slug,omitempty"`
	AppKeyID string `json:"app_key_id,omitempty"`
	// timestamps: int64 Unix epoch milliseconds (UTC). Wire format switched
	// from RFC3339 strings in v1.0.3-alpha — see the design doc at
	// roadmap20260320/技术实现/update/20260424-时间戳统一为int64毫秒-data-service.md.
	// Why: SQLite storage of time.Time via Go's default String format
	// broke strftime-based hour bucketing on the query side.
	EventTime aikeytime.Millis `json:"event_time"`
	// schema + source metadata
	SchemaVersion int              `json:"schema_version"`
	RequestCount  int              `json:"request_count"`
	OccurredAt    aikeytime.Millis `json:"occurred_at"`
}

// ReportOpts collects all context needed to build a ReportableEvent.
type ReportOpts struct {
	StartTime          time.Time
	FinishedAt         time.Time
	SourceSeq          *int64
	Route              *vkeys.ResolvedRoute
	ProxyConfigVersion string
	LoggedInAccountID  string // fallback account_id for personal keys
	BearerToken        string // the full aikey-namespace bearer token from the request (aikey_team_* / aikey_personal_* etc.)
	ProxyInstanceID    string
	// Delivery integrity (2026-05-30). SourceID is the vault's stable source
	// identity; SourceSeq is the per-source never-reused sequence allocated by
	// the proxy's SeqAllocator just before building this event. Leave SourceSeq
	// nil for events that must not participate in gap detection (e.g. canary).
	SourceID string
	// UpstreamRequestID is the provider's own request id from response headers
	// (anthropic: `request-id`, openai/kimi: `x-request-id` or
	// `openai-request-id`). Carried through so support can pivot from a local
	// ODS row to provider-side logs.
	UpstreamRequestID string
	// RequestPath is the inbound r.URL.Path — see ReportableEvent.RequestPath.
	RequestPath string
	Completion  string
	// UI anchor fields (see ReportableEvent docs for semantics).
	// SessionID comes from the X-Claude-Code-Session-Id request header.
	// Completion defaults to "complete" if left empty.
	SessionID   string
	Model       string
	Region      string
	EndpointURL string
	// StopReason is the raw termination string from the provider; pass
	// through un-normalized. BuildReportableEvent omits the JSON field
	// when empty.
	StopReason string
	ErrorType  string
	// ErrorMessage is the truncated upstream error body (set on 4xx/5xx). The
	// proxy captures it so the usage-detail expand can show the real provider
	// reason, not just the generic HTTP status text (which lands in ErrorCode).
	ErrorMessage     string
	RealKey          string // decrypted provider key (for hashing only, never stored)
	SourceVersion    string
	ClientVersion    string
	EventID          string
	LoadedControlSeq int64
	// Cost-pricing audit (v1.0.0-rc.8): reasoning tokens + upstream region/endpoint.
	ReasoningTokens          int
	CacheCreationInputTokens int
	// Optional cache breakdown. Leave zero for providers without caching;
	// BuildReportableEvent will omit these fields from the JSON event.
	CacheReadInputTokens int
	OutputTokens         int
	InputTokens          int
	StatusCode           int
}

// BuildReportableEvent creates a ReportableEvent from the proxy request context.
func BuildReportableEvent(opts *ReportOpts) ReportableEvent {
	route := opts.Route
	now := opts.FinishedAt
	nowMs := aikeytime.FromTime(now)
	startMs := aikeytime.FromTime(opts.StartTime)

	var inTok, outTok, totalTok int64
	inTok = int64(opts.InputTokens)
	outTok = int64(opts.OutputTokens)
	// 方案 A (2026-06-04): inTok is now the PURE (uncached) input. total_tokens must
	// stay the FULL token count, so add both cache buckets back in: pure input +
	// cache_read + cache_creation + output. (Pre-方案-A inTok was the total incl.
	// cache, so total was inTok+outTok; this keeps total_tokens byte-identical while
	// input_tokens alone became pure.) See
	// roadmap20260320/技术实现/update/20260604-token-input-纯输入语义治本-方案A.md.
	totalTok = inTok + int64(opts.CacheReadInputTokens) + int64(opts.CacheCreationInputTokens) + outTok

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
		EventID:            opts.EventID,
		UpstreamRequestID:  opts.UpstreamRequestID,
		RequestPath:        opts.RequestPath,
		ProxyInstanceID:    opts.ProxyInstanceID,
		SourceID:           opts.SourceID,
		SourceSeq:          opts.SourceSeq,
		SchemaVersion:      1,
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
		ReasoningTokens:          int64PtrIfNonZero(opts.ReasoningTokens),
		Region:                   strPtrIfNonEmpty(opts.Region),
		EndpointURL:              strPtrIfNonEmpty(opts.EndpointURL),

		StopReason: opts.StopReason,

		RequestStatus:  status,
		HTTPStatusCode: &opts.StatusCode,
		ErrorCode:      opts.ErrorType,
		ErrorMessage:   opts.ErrorMessage,

		SessionID:  opts.SessionID,
		KeyLabel:   deriveKeyLabel(route),
		Completion: completionOrDefault(opts.Completion),
	}

	// Phase 4 §5.3: App pipeline attribution. Mirror the buildBaseEvent
	// logic in proxy.go so the two event shapes (local + wire) agree on
	// what app made the call. Gated on RouteSource == "app" so legacy
	// /v1/... requests omit these fields (omitempty drops them on wire).
	switch route.RouteSource {
	case "app":
		ev.AppSlug = route.AppSlug
		ev.AppKeyID = route.AppKeyID
		if route.FollowUserActive {
			ev.AppMode = "follow-active"
			ev.BoundVia = "default" // follow-active reads the user's default profile binding
		} else {
			ev.AppMode = "isolated"
			ev.BoundVia = "app:" + route.AppSlug
		}
		ev.RequestedModel = opts.Model
		ev.ResolvedProvider = route.ProviderCode
	case "probe":
		// Probe pipeline attribution (BR-rc.5-54, 2026-05-25): when
		// trust-local (or any future first-party plugin) fires a
		// `/probe/<alias>/v1/messages` request with its compile-time
		// constant bearer, the probe URL itself carries NO app slug —
		// the proxy only learns who's calling by reverse-mapping the
		// bearer. Without this attribution, every successful manual
		// `Trust Check` probe lands in ODS with `app_slug=NULL`, so
		// the `/user/apps/<slug>` dashboard's `WHERE app_slug=...`
		// filter shows ONLY the orphan `/apps/<slug>/...` rows (often
		// failures) and HIDES the real successful probe traffic →
		// user sees "3 requests, 0 tokens" while the feature is
		// actually working — UX-broken honesty hole.
		//
		// We deliberately do NOT set AppKeyID / AppMode / BoundVia
		// here: those are App-pipeline-specific (probe has no app_keys
		// row, no profile binding, the alias is explicit in the URL).
		// Only AppSlug is filled — enough to make the dashboard whole
		// without polluting downstream consumers that key off
		// AppMode/BoundVia semantics.
		if slug := firstPartyAppSlugForBearer(opts.BearerToken); slug != "" {
			ev.AppSlug = slug
		}
	case "oauth":
		if route.AppSlug == "" {
			break
		}
		// OAuth-direct attribution (2026-05-26, usage-by-key dashboard fix):
		// the OAuth path now carries a UA-derived AppSlug (see
		// pipelines.go's handlePathPrefixRoute and the requirements doc
		// at workflow/CI/requirements/2026-05-26-usage-by-key-app-attribution.md).
		// Forward it to the event payload so the dashboard can collapse
		// multi-session noise per (identity, app_slug). Unlike the App
		// pipeline branch above we deliberately DO NOT set
		// AppKeyID / AppMode / BoundVia — those are App-pipeline
		// authorization fields and have no meaning for a UA-derived
		// label. Same scoping as the probe branch.
		//
		// Trust note: route.AppSlug here originates from a client-
		// controlled User-Agent header and can be spoofed. This signal
		// is display-only — never use it for authorization or billing.
		ev.AppSlug = route.AppSlug
	}

	// Stamp the content hash over the metering tuple AS STORED in ev. Use the
	// raw int64 values (cache fields deref-or-zero exactly as the collector
	// will: a nil/omitted cache field on the wire is hashed as 0 on both sides),
	// so client-stamped and server-recomputed bytes are identical. See
	// pkg/usagehash for why these specific fields and why no omitempty.
	ev.ContentHash = usagehash.Compute(usagehash.Input{
		InputTokens:              inTok,
		OutputTokens:             outTok,
		TotalTokens:              totalTok,
		CacheReadInputTokens:     int64(opts.CacheReadInputTokens),
		CacheCreationInputTokens: int64(opts.CacheCreationInputTokens),
		Model:                    opts.Model,
		ProviderCode:             route.ProviderCode,
	})

	return ev
}

// firstPartyBearerToSlug maps a first-party app's compile-time constant
// bearer back to its slug, so probe-pipeline events can be attributed
// to the right app in dashboards (see BuildReportableEvent above).
//
// **Drift 防退化**: this map's KEY set MUST equal the bearer set in
//   - aikey-proxy/internal/proxy/dispatch.go::firstPartyAppBearerWhitelist
//   - aikey-proxy/internal/vault/route_token_form.go::firstPartyAppBearerWhitelist
//   - aikey-proxy/internal/supervisor/team_token_normalize.go::firstPartyAppBearerWhitelist
//   - aikey-cli/src/migrations.rs::DEGRADE_DETECTOR_FIRST_PARTY_BEARER
//   - ai-degrade-detector/server_local/services/check_orchestrator.py::FIRST_PARTY_APP_KEY
//
// Adding a new first-party app means touching ALL of these — same
// lockstep convention as the existing 3 whitelist copies.
var firstPartyBearerToSlug = map[string]string{
	"aikey_app_internal_degrade_detector_v1": "degrade-detector",
}

// firstPartyAppSlugForBearer returns the slug owning `bearer`, or empty
// string if the bearer isn't a known first-party constant. Empty result
// MUST cause the caller to skip AppSlug attribution (don't fabricate).
func firstPartyAppSlugForBearer(bearer string) string {
	return firstPartyBearerToSlug[bearer]
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

// strPtrIfNonEmpty returns a pointer to s, or nil when empty — so omitempty
// drops the field from the wire event (region/endpoint_url are absent for
// direct providers / events without routing info).
func strPtrIfNonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// hashIfNotEmpty returns a SHA-256 hex digest, or empty string.
func hashIfNotEmpty(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
