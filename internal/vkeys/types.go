package vkeys

import "context"

// ResponseTransform is an optional post-response hook. When set on a
// ResolvedRoute, the proxy's serveRoute() ModifyResponse closure invokes
// it on the upstream's response body AFTER token extraction but BEFORE
// re-buffering for the client. Returning a non-nil error fails the
// request with HTTP 502 ("upstream contract violated; translation
// failed"); zero return value means no body change.
//
// Phase 4 / Phase 2 use:  app-pipeline-only protocol translation
// (Anthropic response → OpenAI response). Tier 1 / Tier 2 routes leave
// this field nil; serveRoute's behavior for those routes is byte-
// identical to before this field existed.
//
// Why this lives on ResolvedRoute (not as a parameter to serveRoute):
// (1) the field is OPTIONAL — Tier 1/2 routes pay zero cost (one nil
// check), (2) keeping the serveRoute signature stable avoids ripple
// changes across all callers (oauth / personal / team / app), (3)
// the translator code stays in apppipe + pkg/protocol-translator and
// never leaks into the shared proxy package's logic. See the audit at
// `workflow/CI/e2e/cases/2026-05-20-translate-openai-to-anthropic.md`
// §0 for the isolation rationale.
//
// Signature uses the standard error interface (not *translator.TranslateError)
// to keep vkeys decoupled from pkg/protocol-translator. apppipe's
// translate.go wraps the typed error before assigning the closure.
type ResponseTransform func(ctx context.Context, body []byte) ([]byte, error)

// ResolvedRoute contains everything needed to forward a request after
// virtual key resolution.
type ResolvedRoute struct {
	// Bindings holds the exact routes that share one bearer token. It is set
	// for a multi-binding managed VK; dispatch selects one by requested client
	// route + Protocol before any credential or upstream field is consumed.
	Bindings         []*ResolvedRoute
	ObserverRegistry any
	// ── Phase 4 M2 plugin observer hook fields (App pipeline only) ────
	//
	// Both fields are nil on Tier 1 / Tier 2 (legacy) routes — only
	// handleAppPipeline sets them, gated on observerRegistry being
	// attached AND having at least one active observer. The streaming
	// path's hooks (in streamDrainer) check ObserverContext != nil
	// first, so legacy paths cost a single nil dereference per
	// streamed request and zero extra allocations.
	//
	// **Field type intentionally `any`** (not `*observer.RequestContext`
	// / `*observer.Registry`): pkg/vkeys must not import pkg/observer
	// or any consumer package. Keeping these as opaque pointers in
	// vkeys preserves the layering — the observer-aware code lives in
	// internal/proxy (which imports both vkeys + observer) and does
	// the type assertion at the hook point.
	//
	// This is the same pattern used by ResponseTransform above
	// (declared as `ResponseTransform` typedef in this package rather
	// than importing translator), keeping vkeys at the bottom of the
	// dependency graph.
	ObserverContext any
	// ── Phase 2 protocol-translation hook (App pipeline only) ─────────
	//
	// ResponseTransform is set by apppipe.MaybeTranslateRequest when the
	// inbound URL protocol differs from the binding's upstream provider
	// protocol AND a translator pair is registered (e.g. OpenAI → Anthropic).
	// serveRoute's ModifyResponse calls it on a successful upstream
	// response body AFTER token extraction so usage events keep using
	// the upstream's native shape, and BEFORE re-buffering for the
	// client so the client sees the inbound shape.
	//
	// Tier 1 (virtual keys) / Tier 2 (raw provider keys) routes leave
	// this nil; the serveRoute ModifyResponse code path for those
	// routes is byte-identical to before this field existed (a single
	// nil check).
	ResponseTransform ResponseTransform
	ProviderCode      string
	CredentialID      string
	// PlaintextKey is set for team-managed virtual keys loaded from
	// managed_virtual_keys_cache.  When non-empty it is used directly,
	// bypassing the per-request vault alias lookup.
	PlaintextKey string
	// Anchor fields for usage reporting.
	// For team-managed keys: populated from ManagedKey metadata.
	// For OAuth accounts: OAuthIdentity is the email/display name (for audit only).
	OrgID              string
	AccountID          string
	SeatID             string
	OAuthIdentity      string // Email or display name (OAuth only, for audit/usage reporting)
	BindingID          string // empty if not available in local cache (schema gap)
	ProviderID         string // empty if not available in local cache (schema gap)
	VirtualKeyID       string
	ProtocolType       string
	Provider           string // "openai", "anthropic"
	CredentialRevision string
	VirtualKeyRevision string
	// RouteSource is the origin classification set at registry construction
	// time: "personal_byok" (static YAML), "team" (managed cache),
	// "personal" (vault personal route token), "oauth" (vault OAuth token),
	// "app" (Phase 4 third-party Agent route token).
	// Used by downstream consumers (WAL event, CLI status line, watch) to
	// derive user-facing labels without fragile prefix parsing on VirtualKeyID.
	RouteSource string
	// ── App pipeline fields (RouteSource == "app" only) ────────────────────
	//
	// Phase 4 routes are loaded into the registry at startup like personal /
	// OAuth, but they DO NOT carry a static (Provider, BaseURL, KeyAlias)
	// triple. Those are resolved per-request by the App pipeline via
	// vault.GetProviderBindingWithScope("app:<slug>", protocol), so the
	// upstream credential follows the app's binding policy rather than being
	// frozen at load time.
	//
	// Consumers that touch ResolvedRoute today (personal/team/oauth callers)
	// see these as zero-values and are unaffected. The App pipeline reads
	// them after Registry.Resolve to recover the app context required for
	// authorization + protocol-set enforcement + audit events.

	// AppSlug carries two distinct semantics depending on RouteSource:
	//
	//   1. RouteSource == "app" — REGISTERED. The app_records.slug this
	//      token was issued for. URL `/apps/<AppSlug>/<protocol>/v1/...`
	//      must match this exactly or the request is rejected with
	//      APP_MISMATCH (defense against token reuse across apps).
	//      Authoritative, server-derived, used for authorization.
	//
	//   2. RouteSource == "oauth" — UA-DETECTED. The slug returned by
	//      uaattribution.Default().Match(r.Header["User-Agent"]) at
	//      handler entry. Display-only, used by the usage-by-key
	//      dashboard to attribute traffic to a client app (Claude Code /
	//      Cursor / Cline / "unknown-app" fallback). Trivially
	//      spoofable — never use for authorization or billing.
	//
	// Other RouteSource values ("personal", "team", "probe") leave this
	// field empty.
	//
	// Why one field for both: avoids new schema columns (慎重新建数据结构)
	// and the only consumer that distinguishes — apppipe's APP_MISMATCH
	// validator — runs strictly inside the App pipeline where RouteSource
	// is guaranteed "app". See:
	//   workflow/CI/requirements/2026-05-26-usage-by-key-app-attribution.md
	AppSlug string
	// AppKind is "first-party" or "third-party" (mirrors app_records.app_kind).
	// Gates the follow-user-active mode — only first-party apps are allowed
	// to share the user's default profile binding. Re-checked at request time
	// in apppipe/resolve.go even though it's also checked at register time,
	// so vault tampering can't escalate privileges.
	AppKind string
	// AppKeyID is the app_keys.key_id UUID — the audit anchor written into
	// EVENTS for every request routed through this token. Independent of
	// the route_token plaintext so rotation history can be traced (one slug
	// over time may have multiple key_ids).
	AppKeyID string
	BaseURL  string // upstream base URL
	// ProtocolFamily is the wire-protocol category of the upstream binding,
	// derived from pkg/providerroutes (yaml provider_fingerprint single
	// source of truth). ProtocolType carries the credential's independent
	// protocol axis (for example provider=mock with protocol_type=anthropic
	// or openai_compatible); ProtocolFamily is the normalized wire family:
	//
	//   "anthropic"          — Anthropic messages API (anthropic upstream)
	//   "openai_compatible"  — OpenAI chat-completions API (openai, kimi,
	//                          deepseek, qwen, openrouter, groq, ...)
	//   "gemini"             — Google Gemini API
	//
	// Filled in handleAppPipeline at Stage 6 via
	// provider.Routes().ByProvider(binding.ProviderCode).Protocol.
	//
	// Required by the Phase 4 M2 plugin observer (degrade-detector rhythm
	// observer) to pick the correct SSE parser without re-doing the
	// provider→protocol yaml lookup. See plugin-架构设计.md §3.2.
	ProtocolFamily string
	KeyAlias       string   // vault entry alias for real key (static config keys)
	AllowedModels  []string // nil means allow all
	// ── Primary/fallback chain (P0a upstream fallback, task 2.0) ──────────
	//
	// Priority is this binding's position within its (VirtualKeyID,
	// ProtocolType) chain — 1 = primary, ascending. The candidate sequence is
	// built by sorting on it.
	//
	// 🔴 FallbackRole is DISPLAY ONLY (I19). It is derived from the order
	// upstream, and ordering decisions here must read Priority: two
	// independently-writable fields can always be made to contradict each other
	// ("first in line, labelled F1"), and a reader has no way to tell which one
	// the runtime obeyed.
	Priority     int64
	FallbackRole string
	// RouteGroupID / RouteGroupName name the org-level template this binding was
	// generated from.
	//
	// 🔴 Empty is NOT "a chain of one". No group at all means a row written
	// before route groups existed → single-shot, byte-identical to the
	// pre-upgrade behavior. A group with one member means an administrator built
	// a chain and most likely believes it is redundant — so its failure gets
	// UPSTREAM_FALLBACK_UNCONFIGURED, pointing at the thing they need to fix.
	// Collapsing the two into one error would send half of the people who see it
	// in the wrong direction.
	RouteGroupID   string
	RouteGroupName string
	// FollowUserActive flips the App pipeline's profile_id selection from
	// "app:<slug>" (isolated mode, the default) to "default" (the user's
	// own active profile). first-party only; see AppKind above for the
	// defense-in-depth check.
	FollowUserActive bool

	// ── Oauth-group (channel ③) route fields (N7c) ─────────────────────────
	// OauthGroupID != "" marks a GROUP virtual key: PlaintextKey is empty and the
	// dispatch resolver (N8) picks a candidate account from GroupAccounts (ranked
	// via pkg/seatassign for SeatID), reads its token from GroupRuntime, and
	// injects it. Empty for direct-bind VKs → existing path, byte-unchanged.
	OauthGroupID string
	// GroupAccounts: candidate account list JSON (structural). GroupRuntime:
	// per-account token/key material JSON (channel ③, encrypted, proxy-pulled;
	// NEVER refresh_token). RoutingConfig: the group's routing knobs JSON.
	GroupAccounts string
	GroupRuntime  string
	RoutingConfig string
	// EgressProxyURL is the RESOLVED account's optional per-account egress proxy
	// (§11.7, P7), copied here per-request by handleOauthGroupRoute from the
	// picked GroupRuntimeAccount. When set, serveRoute selects a per-account
	// egress transport (single-hop, or 2-hop chained through the node's socks5
	// front proxy) so THIS account's outbound leaves via its own IP. Empty for
	// every non-group route → the node-level egress transport applies unchanged.
	// Held only in this per-request struct + in-memory material — never written
	// to the proxy's config file.
	EgressProxyURL string
}

// IsModelAllowed checks if the given model is permitted by this route.
// Returns true if AllowedModels is nil/empty (all models allowed).
func (r *ResolvedRoute) IsModelAllowed(model string) bool {
	if len(r.AllowedModels) == 0 {
		return true
	}
	for _, m := range r.AllowedModels {
		if m == model {
			return true
		}
	}
	return false
}
