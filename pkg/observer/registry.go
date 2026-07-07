// Package observer is aikey-proxy's domain-neutral observer framework for
// the App pipeline. It provides a `StreamingObserver` interface, an
// `Observer` descriptor, a `RegisterObserver` self-registration helper,
// and a `DefaultVaultEnableCheck` shared enable predicate. The package
// has zero knowledge of any specific observer's business semantics
// (e.g., "rhythm" / "degrade-detector" / "RhythmEvidence" are not
// mentioned anywhere in this file or its tests).
//
// The framework was designed to satisfy the four fault-isolation
// dimensions enumerated in plugin-架构设计.md §6:
//
//  1. Code isolation       — observer business types never appear in
//     the observer package's public surface
//  2. Architecture isolation — observer panics / leaks cannot bring
//     the proxy main flow down; reporters use
//     their own HTTP transport, etc.
//  3. Exception isolation  — payload aliasing, fan-out backpressure,
//     ctx propagation, panic rate-limiting are
//     all P0/P1 invariants pinned into this
//     code (see numbered comments below)
//  4. Decoupling           — adding a new observer requires only
//     `init()` self-registration + a single
//     `import _` line in proxy main; the
//     registry never special-cases any slug
//     apart from a hard-coded first-party
//     allowlist (R2 first defense line).
//
// Lifecycle (per request, in the App pipeline):
//
//  1. apppipe handler calls `Registry.NotifyStart(ctx, req)` after
//     authentication + binding resolution succeed.
//  2. Drainer reads upstream SSE; for each frame the handler calls
//     `Registry.NotifySSEEvent(ctx, req, eventType, payload)` BEFORE
//     `ResponseTransform` (if any) reshapes the chunk. This ordering
//     is doc-anchored in proxy/apppipe to prevent later refactors
//     from moving the hook past the translator.
//  3. After upstream EOF / disconnect, handler calls
//     `Registry.NotifyEnd(ctx, req, totalLatencyMs)`.
//
// All three Notify* methods are non-blocking: they hand events off to a
// per-(request × observer) consumer goroutine via a buffered channel
// (size 32). The drainer never waits on observer work.
package observer

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Public types — these are the entire contract surface for observer packages.
//
// **DO NOT** add observer-specific fields to RequestContext or expose
// observer-private types here. New observers extend the framework only by
// implementing StreamingObserver; if you find yourself wanting to add a
// "ChunkPayload" or "RhythmEvidence" field, the design is wrong — those
// belong inside the observer package, not on the registry surface.
// ---------------------------------------------------------------------------

// StreamingObserver is the only contract a streaming observer must
// implement. The three hooks are deliberately the minimum sufficient set:
//
//   - 1 hook (end-only) would lose chunk-level timing data, breaking
//     the rhythm-based detector that motivated this framework.
//   - 10 hooks (header-received, first-byte, tool-call-start, ...) would
//     bloat the contract surface; each added hook is a versioning
//     burden across all observers.
//
// Three hooks (start / per-event / end) cover the union of observed
// use cases (rhythm counting, billing-on-stream, prompt-injection
// sniffing) without overcommitting.
//
// Implementations MAY retain the `payload` byte slice handed to
// OnSSEEvent — the registry hands over a private copy (see
// `NotifySSEEvent` for the aliasing invariant). The implementation MUST
// NOT mutate the slice expecting the change to propagate elsewhere;
// future observers will see their own copies.
type StreamingObserver interface {
	// OnRequestStart fires once per request, after auth + binding
	// succeed and before any upstream bytes are read. Use it to
	// initialize per-request state (typically keyed by req.TraceID).
	OnRequestStart(ctx context.Context, req *RequestContext)

	// OnSSEEvent fires once per upstream SSE event. eventType is the
	// already-parsed "event:" line (or "" when absent); payload is the
	// already-parsed "data:" line, byte-identical to what the upstream
	// sent — translator processing happens AFTER this hook returns.
	OnSSEEvent(ctx context.Context, req *RequestContext, eventType string, payload []byte)

	// OnRequestEnd fires once per request after upstream EOF /
	// disconnect / shutdown. totalLatencyMs is wall-clock from
	// OnRequestStart to here. Use this hook to finalize + submit
	// evidence; the request's state map entry is cleaned up
	// immediately after this returns.
	OnRequestEnd(ctx context.Context, req *RequestContext, totalLatencyMs int)
}

// FullPayloadObserver is an OPTIONAL capability interface. An observer that
// needs the raw request body (the prompt) — i.e. the reserved
// "payload_level=full" — implements it; the registry surfaces the union via
// Registry.WantsFullPayload so the proxy buffers the body ONLY when some
// active observer actually wants it (zero cost otherwise).
//
// It is deliberately a separate optional interface rather than a fourth
// StreamingObserver hook: the 3-hook contract stays minimal (see the
// StreamingObserver doc), and observers that don't need the body — the common
// case (rhythm, billing-on-stream) — neither implement it nor pay for it.
//
// WantsFullPayload MAY return a value that changes over the process lifetime
// (e.g. an enterprise audit observer returns the live org policy flag), so the
// registry re-evaluates it per request rather than caching at build time.
type FullPayloadObserver interface {
	WantsFullPayload() bool
}

// RequestContext is the per-request metadata observers see. Mirrors the
// schema documented in plugin-架构设计.md §3.2; new fields require a
// design-doc update so observers can rely on a stable shape.
//
// **Critical**: ProtocolFamily here is the UPSTREAM real wire family —
// derived from body.model → provider code → providerroutes yaml. It is
// NOT the inbound URL's wire format (the inbound URL might be
// /v1/chat/completions while the upstream is Anthropic, or vice-versa).
// Observers should pick their SSE parser by ProtocolFamily.
type RequestContext struct {
	StartedAt       time.Time
	metadataJSONErr error
	SessionID       string
	TraceID         string // per-request UUID; observers use as state-map key
	ProviderID      string // canonical provider code, e.g. "anthropic", "kimi_code"
	ProtocolFamily  string // "anthropic" | "openai_compatible" | "gemini" | "" (unknown)
	RequestedModel  string // body.model as sent by the client
	ResolvedModel   string // upstream-reported model, may differ (alias resolution)
	AppKeyID        string
	// KeyAlias is the vault-side credential alias that this request
	// resolved to (e.g. "my-anthropic"). For follow-active first-party
	// apps it equals the user's `aikey use` selection. trust-local's
	// LocalObservation table uses alias_name as a primary aggregation
	// key, so observers MUST receive it via this field rather than
	// re-derive it from app_key_id at report time. Empty string is a
	// valid value (some routes — e.g. team-managed virtual keys — have
	// no per-user alias); observers in that case should fall back to
	// AppKeyID for attribution.
	KeyAlias string
	AppMode  string // "isolated" | "follow-active"
	// OrgID / OwnerAccountID are the multi-tenant attribution identity — the
	// tenant and the developer (seat owner) this request is billed/attributed
	// to. Populated by the proxy from the resolved route, mirroring the usage
	// path's single-source rule (route.OrgID; route.AccountID ?? logged-in
	// account) so observers never invent a divergent attribution. These are
	// request IDENTITY (the same category as SessionID / KeyAlias above), NOT
	// observer-derived state — so they belong here, not inside an observer.
	// Empty OrgID means a personal (non-org) request.
	OrgID          string
	OwnerAccountID string
	// SeatID is the org seat this request's HUMAN belongs to, from
	// route.SeatID — the same field usage events carry (reportable.go). Why
	// it exists SEPARATELY from OwnerAccountID (2026-07-07, org 624a2488
	// live incident): for a shared OAuth-pool VK the route's AccountID is
	// the VK OWNER (pool creator), not the employee at the terminal —
	// audit records keyed only on owner filed under a stranger seat while
	// usage (seat-keyed UI) attributed correctly. Empty for personal keys
	// and legacy vault rows that pre-date seat stamping.
	SeatID string
	// Stream is the SPEC §1.4.1 stream name this request emits under
	// (StreamUserChat / StreamAppPipeline / StreamProbe). Set by the
	// Registry on the way into NotifyStart so observers can read it
	// without re-deriving from path; the caller's stream argument to
	// NotifyStart is authoritative — this field exists solely to
	// surface the same value through the existing OnRequestStart /
	// OnSSEEvent / OnRequestEnd contract (which never grew its own
	// stream parameter to keep the StreamingObserver interface stable).
	Stream       string
	AppSlug      string
	metadataJSON []byte
	// RequestBody is the raw client request body (the prompt), populated by
	// the proxy ONLY when an active observer declares it wants the full
	// payload (see FullPayloadObserver / Registry.WantsFullPayload). This is
	// the framework's reserved "payload_level=full" capability — NOT
	// observer-derived state (which the §"DO NOT add fields" rule forbids),
	// but the raw request data itself, the request-side analog of the
	// `payload []byte` already handed to OnSSEEvent. Nil when no active
	// observer wants full payload (the default — zero memory cost), or when
	// the body exceeded the proxy's capture cap. Observers MUST treat it as
	// read-only; the proxy hands over its own buffered copy.
	RequestBody []byte
	// metadataJSON* implement the MetadataJSON() lazy cache. Private —
	// observers must use the method, not the raw fields. sync.Once gives
	// us thread-safe "marshal at most once, even under concurrent observer
	// goroutine load" with a single atomic load on the fast path.
	//
	// Why private: keeps the wire format change point at MetadataJSON
	// only; nothing outside this file can poke the cache (and accidentally
	// produce inconsistent bytes per observer).
	metadataJSONOnce sync.Once
}

// metadataPayload is the lazy-cached JSON shape MetadataJSON() emits.
// Locked at v=1 — bumping the version means an existing NDJSON consumer
// reading from disk has to opt in. omitempty everywhere except v so the
// wire format stays compact for the common-case fields that aren't set
// in every pipeline (App-side fields are blank for user_chat etc.).
//
// Field tags mirror the wire format documented inline in MetadataJSON's
// doc comment; tests pin this so a future refactor sees the breakage
// rather than silently shifting field names.
type metadataPayload struct {
	AppKeyID        string `json:"app_key_id,omitempty"`
	TraceID         string `json:"trace_id,omitempty"`
	Stream          string `json:"stream,omitempty"`
	Provider        string `json:"provider,omitempty"`
	Alias           string `json:"alias,omitempty"`
	AppSlug         string `json:"app_slug,omitempty"`
	AppMode         string `json:"app_mode,omitempty"`
	RequestedModel  string `json:"requested_model,omitempty"`
	ResolvedModel   string `json:"resolved_model,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	ProtocolFamily  string `json:"protocol_family,omitempty"`
	V               int    `json:"v"`
	StartedAtUnixMs int64  `json:"started_at_unix_ms,omitempty"`
}

// MetadataJSON returns a stable JSON serialization of the per-request
// metadata fields observers commonly need. Lazily computed on first call
// and cached across subsequent calls — including concurrent observer
// goroutine calls; sync.Once gives us atomic fast path + at-most-once
// marshal under contention.
//
// Multiple observers sharing the same RequestContext (the framework hands
// the same *RequestContext to every observer's consumer goroutine) all
// pay one json.Marshal in aggregate, regardless of how many observers
// call this. Critical optimisation for the 5+ observer / 1000+ req/sec
// case: with N observers each marshaling independently the proxy spends
// O(N) CPU per request on duplicate serialization; this helper collapses
// that to O(1).
//
// Wire format is v=1 (see metadataPayload). Locked — any change is a
// breaking event for downstream NDJSON consumers; bump v and document
// the migration before altering tags.
//
// The returned slice is SHARED with all callers — observers MUST NOT
// mutate it. Copy via `append([]byte(nil), b...)` before any modification.
//
// Returns the marshal error from the first attempt; cached too, so
// subsequent calls see the same error without re-trying (consistent
// per-request behavior — a corrupt RequestContext should produce the
// same failure for every observer).
func (r *RequestContext) MetadataJSON() ([]byte, error) {
	r.metadataJSONOnce.Do(func() {
		payload := metadataPayload{
			V:               1,
			TraceID:         r.TraceID,
			Stream:          r.Stream,
			Provider:        r.ProviderID,
			Alias:           r.KeyAlias,
			AppSlug:         r.AppSlug,
			AppKeyID:        r.AppKeyID,
			AppMode:         r.AppMode,
			RequestedModel:  r.RequestedModel,
			ResolvedModel:   r.ResolvedModel,
			SessionID:       r.SessionID,
			ProtocolFamily:  r.ProtocolFamily,
			StartedAtUnixMs: r.StartedAt.UnixMilli(),
		}
		r.metadataJSON, r.metadataJSONErr = json.Marshal(&payload)
	})
	return r.metadataJSON, r.metadataJSONErr
}

// Stream name constants for Observer.Streams declarations and Notify*
// call sites. Mirror the vocabulary defined in SPEC
// `workflow/CI/requirements/2026-05-23-credential-mode-architecture.md` §1.4.1.
//
// Adding a new stream is a coordinated change:
//
//  1. Add a new entry here + to the SPEC's §1.4.1 table
//  2. Add `NotifyStart/End/SSEEvent` call sites in the proxy that emit it
//  3. Update relevant Observer descriptors' Streams to declare interest
//
// We use string typed constants (rather than an enum / iota) so
// observers from external repositories (ai-degrade-detector/proxy-plugin/*)
// can hardcode the literal value when this package's version skews.
const (
	// StreamUserChat — traffic on legacy `/v1/...` and `/<provider>/v1/...`
	// (the user's primary chat surface).
	StreamUserChat = "user_chat"

	// StreamAppPipeline — traffic on `/apps/<slug>/v1/...` (App pipeline,
	// SPEC §1.2 modes A/B).
	StreamAppPipeline = "app_pipeline"

	// StreamProbe — traffic on `/probe/<alias>/v1/...` (Probe pipeline,
	// SPEC §1.3 mode C).
	StreamProbe = "probe"
)

// AllStreams returns the full set of valid stream names. Used by
// RegisterObserver to validate Observer.Streams entries and by
// observers that want to subscribe to everything (e.g., ndjson-fanout).
//
// Order is stable: user_chat, app_pipeline, probe.
func AllStreams() []string {
	return []string{StreamUserChat, StreamAppPipeline, StreamProbe}
}

// Observer is the descriptor an observer package registers at init()
// time. The descriptor is a value type — registering twice with the
// same Name will panic at startup (deliberate; ambiguous instances are
// a bug, not a runtime condition).
type Observer struct {
	// Build constructs the observer implementation from the proxy
	// config block (e.g. yaml `observers.<name>` map). Build is
	// called once at proxy startup; if it returns an error the
	// observer is logged as unavailable and skipped — the proxy
	// continues to start. This is intentional: a misconfigured
	// observer must NEVER block proxy main flow.
	Build func(cfg map[string]any) (StreamingObserver, error)
	// Name uniquely identifies this observer within the proxy
	// process. Lowercase letters / digits / dashes.
	Name string
	// OwnerAppSlug is the first-party application this observer
	// belongs to. Must be present in FirstPartyAllowlist below.
	OwnerAppSlug string
	// Streams is the explicit list of stream names this observer cares
	// about (see Stream* constants and SPEC §1.4.1). The Registry skips
	// Notify dispatch for any stream not in this list. MUST be non-empty —
	// an empty Streams is a registration bug (the observer would silently
	// receive no events, hard to diagnose), so RegisterObserver panics.
	//
	// Pick the minimum:
	//   - rhythm (App-pipeline-only)        → []string{StreamAppPipeline}
	//   - generic file fanout (everything)  → AllStreams()
	//   - compliance detector (user only)   → []string{StreamUserChat}
	//
	// Entries are validated against AllStreams() at registration time;
	// any unknown stream name panics.
	Streams []string
}

// HandlesStream reports whether the observer's Streams declaration
// includes the named stream. Used by Registry dispatch to skip irrelevant
// observers. Empty Streams returns false for every name (registration
// rejects empty Streams at startup, but the predicate stays defensive).
func (o *Observer) HandlesStream(name string) bool {
	for _, s := range o.Streams {
		if s == name {
			return true
		}
	}
	return false
}

// FirstPartyAllowlist is the slug whitelist for observer registration.
// Only first-party AiKey-team-owned applications appear here; any
// `RegisterObserver` call with a slug outside the allowlist panics at
// process startup (i.e., before any request is served).
//
// This is the R2 first defense line; the other two (CLI-side
// `--first-party` flag gating + manifest install-time check) live in
// aikey-cli / aikey-control. The three together make it materially
// harder for a third-party fork to inject a malicious observer.
//
// Adding a slug here requires:
//   - a separate AiKey-team-maintained repository for the observer
//   - explicit code review on this very line in a separate PR
//   - the observer package must vendor-link, not dynamically load
var FirstPartyAllowlist = map[string]bool{
	"degrade-detector": true,

	// aikey-proxy-core is the synthetic owner slug for proxy-bundled
	// infrastructure observers (currently: ndjson-fanout, P3 step 2c).
	// These observers don't belong to any user-installed first-party
	// app — they're part of aikey-proxy itself, providing generic
	// services (file fanout for vault-declared subscribers) that any
	// future Agent can subscribe to via `aikey app create --observe`.
	//
	// supervisor.buildObserverRegistry special-cases this slug to bypass
	// DefaultVaultEnableCheck (which would look up app_records and
	// reject — no such app row exists for "aikey-proxy-core"). The
	// observer's own Build() is still responsible for noop'ing when
	// no actual subscribers are configured in vault.
	"aikey-proxy-core": true,
}

// ---------------------------------------------------------------------------
// Global registration sink (init-time)
//
// observer packages call RegisterObserver from their own init() functions:
//
//     // ai-degrade-detector/proxy-plugin/rhythm/registration.go
//     func init() {
//         observer.RegisterObserver(observer.Observer{...})
//     }
//
// The proxy main binary picks up registrations via a side-effect import:
//
//     import _ "github.com/aikeylabs/ai-degrade-detector/proxy-plugin/rhythm"
//
// Adding a new observer therefore touches exactly TWO lines in the proxy
// main repo: the import line, and the FirstPartyAllowlist entry. No
// changes to internal/proxy/* are required.
// ---------------------------------------------------------------------------

var (
	registrationMu sync.Mutex
	registrations  []Observer
)

// RegisterObserver records an observer descriptor in the process-global
// registration sink. Idempotent for distinct names; panics if:
//   - OwnerAppSlug is not in FirstPartyAllowlist
//   - Name is already registered (ambiguous descriptors are a bug)
//
// Safe to call from package init() — concurrent init() calls from
// different packages serialize on `registrationMu`.
func RegisterObserver(o Observer) {
	registrationMu.Lock()
	defer registrationMu.Unlock()

	if !FirstPartyAllowlist[o.OwnerAppSlug] {
		// Panic here (not log.Fatal) because this is a startup-time
		// invariant violation; the proxy must refuse to start rather
		// than silently allow an out-of-allowlist observer in.
		panic("observer: refusing registration of '" + o.Name +
			"' — owner slug '" + o.OwnerAppSlug + "' is not in FirstPartyAllowlist; " +
			"first-party observers must be added explicitly via PR")
	}
	if o.Name == "" || o.OwnerAppSlug == "" || o.Build == nil {
		panic("observer: incomplete descriptor — Name, OwnerAppSlug, Build all required")
	}
	// Streams is a required field: an observer with no declared streams
	// would silently never receive events — "failure is invisible" is the
	// anti-pattern the SPEC §1.4 stream routing model explicitly fixes.
	// Better to panic at startup than to ship a dead observer.
	if len(o.Streams) == 0 {
		panic("observer: '" + o.Name + "' must declare Streams (e.g. " +
			"[]string{StreamAppPipeline} for rhythm-style, or AllStreams() " +
			"for generic fanout); empty Streams is silent failure")
	}
	validStreams := map[string]struct{}{}
	for _, s := range AllStreams() {
		validStreams[s] = struct{}{}
	}
	for _, s := range o.Streams {
		if _, ok := validStreams[s]; !ok {
			panic("observer: '" + o.Name + "' declares unknown stream '" + s +
				"'; valid streams are " + joinStrings(AllStreams(), ", ") +
				" (see pkg/observer.Stream* constants)")
		}
	}
	for _, prev := range registrations {
		if prev.Name == o.Name {
			panic("observer: duplicate registration for name '" + o.Name + "'")
		}
	}
	registrations = append(registrations, o)
}

// joinStrings is a tiny strings.Join alternative kept local to avoid
// pulling the strings import for one call site. Matches apppipe's flat-
// import style.
func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += sep + p
	}
	return out
}

// RegisteredObservers returns a snapshot of the current registration
// sink. The proxy startup path uses this to decide which observers to
// Build + Add into a Registry instance. Intended for proxy main / tests
// only; observer packages should never read it.
func RegisteredObservers() []Observer {
	registrationMu.Lock()
	defer registrationMu.Unlock()
	out := make([]Observer, len(registrations))
	copy(out, registrations)
	return out
}

// resetRegistrationsForTest clears the global sink. Test-only — prefixed
// with the standard `…ForTest` convention so calls from production code
// stand out in review.
func resetRegistrationsForTest() {
	registrationMu.Lock()
	defer registrationMu.Unlock()
	registrations = nil
}

// ResetRegistrationsForTest is the exported variant of
// resetRegistrationsForTest for callers in sibling packages (e.g.
// internal/proxy tests) that need to isolate their tests from the
// process-global registration sink. Always pair this with a
// t.Cleanup so leftover registrations from one test don't bleed into
// the next.
//
// Production code MUST NOT call this — the `…ForTest` suffix is the
// convention that surfaces misuse in review.
func ResetRegistrationsForTest() {
	resetRegistrationsForTest()
}

// ---------------------------------------------------------------------------
// VaultGetter — minimal vault surface required by DefaultVaultEnableCheck.
//
// Defined locally as an interface (rather than importing *vault.Reader)
// to keep the package import graph thin and to make unit tests trivial
// (no need to bring up a real vault).
// ---------------------------------------------------------------------------

// VaultGetter is the subset of vault.Reader that DefaultVaultEnableCheck
// needs. Production code passes a real *vault.Reader; tests pass a mock.
type VaultGetter interface {
	GetAppRecord(slug string) (appRecord interface{ GetSlug() string }, err error)
	GetActiveAppKeysForSlug(slug string) (n int, err error)
}

// DefaultVaultEnableCheck returns true iff the given first-party app is
// "live" in the user's vault — i.e., (a) `app_records` has a row for
// this slug AND (b) at least one `app_keys` row exists in status=active.
//
// This predicate is used by `Registry.BuildObservers` to decide whether
// to instantiate an observer at proxy startup. Observers whose owner app
// is not live are quietly skipped (no error, no warning beyond INFO).
//
// Implementing this once in the framework — rather than letting each
// observer roll its own check — keeps the "enabled when app is
// installed" rule consistent across observers and lets future operators
// reason about exactly one switch per app.
func DefaultVaultEnableCheck(slug string, vault VaultGetter, logger *slog.Logger) bool {
	if logger == nil {
		logger = slog.Default()
	}
	rec, err := vault.GetAppRecord(slug)
	if err != nil {
		logger.Warn("observer: vault enable check — GetAppRecord failed",
			"event.name", "proxy.observer.enable_check_failed",
			"slug", slug,
			"error.message", err.Error(),
		)
		return false
	}
	if rec == nil {
		return false
	}
	n, err := vault.GetActiveAppKeysForSlug(slug)
	if err != nil {
		logger.Warn("observer: vault enable check — GetActiveAppKeysForSlug failed",
			"event.name", "proxy.observer.enable_check_failed",
			"slug", slug,
			"error.message", err.Error(),
		)
		return false
	}
	return n > 0
}

// ---------------------------------------------------------------------------
// Registry — runtime instance.
//
// One Registry per proxy process. Built once at startup; `BuildObservers`
// instantiates each registered observer if its enable check passes, and
// from then on `Notify*` calls fan events out to the active set.
//
// Invariants worth reading before extending this struct:
//
//   - The `requests` map is keyed by RequestContext.TraceID and holds
//     per-request consumer goroutine handles. NotifyEnd MUST be called
//     for every NotifyStart, or the consumer goroutines + state-map
//     entries leak. A max-request-age timer (10 minutes) acts as a
//     last-resort safety net (P1-1 invariant).
//
//   - Notify* methods never block on observer work. SSE event delivery
//     uses a buffered channel + non-blocking send (`default` case in
//     the select); when the channel is full the event is dropped and a
//     dropped-event counter is incremented. This is the P0-2
//     fan-out-backpressure invariant.
//
//   - The byte slice handed to NotifySSEEvent is copied exactly once at
//     the boundary (see NotifySSEEvent body) before fan-out. Observers
//     receive a private copy and may retain it; the drainer's read
//     buffer is free to be overwritten as soon as NotifySSEEvent
//     returns. This is the P0-1 payload-aliasing invariant.
// ---------------------------------------------------------------------------

const (
	// notifyChannelBufferSize is the per-(request × observer) buffered
	// channel depth. 32 matches plugin-架构设计.md §6 P0-2 invariant
	// ("5-10 frame buffer with headroom"); raise if you have data that
	// observers genuinely need fuller history, but be aware that bumping
	// this also bumps worst-case memory per concurrent request.
	notifyChannelBufferSize = 32

	// maxRequestAge bounds how long a per-request consumer goroutine
	// stays alive without a matching NotifyEnd. Real LLM streams finish
	// in seconds; 10 minutes is a deliberate "anything past this is a
	// bug" threshold (P1-1 invariant safety net).
	maxRequestAge = 10 * time.Minute

	// panicBudget / panicWindow define the per-observer panic
	// rate-limit budget (P1-2 invariant). At more than `panicBudget`
	// panics within `panicWindow`, the observer is auto-disabled and
	// its `disabled` flag flips on; the proxy keeps serving.
	panicBudget = 60
	panicWindow = 1 * time.Minute

	// crashDumpBudget / crashDumpWindow rate-limit the disk crash-dump
	// emission to avoid flooding the dump directory when an observer
	// panics on every chunk. Below the budget panics still go through
	// GoSafe (recover + dump); above the budget they recover silently
	// + bump a counter only.
	crashDumpBudget = 10
	crashDumpWindow = 1 * time.Minute
)

// Registry is the runtime fan-out instance held by the proxy.
type Registry struct {
	logger *slog.Logger
	// detachedCtxFn is the seam used to build the observer-side
	// context. Production path uses context.WithoutCancel + a
	// max-age timeout; tests substitute their own. Keeping this as a
	// var avoids importing 1.21+ assumptions deeper into the package.
	detachedCtxFn func(parent context.Context) (context.Context, context.CancelFunc)
	requests      sync.Map // map[TraceID]*requestState
	observers     []*activeObserver
	// counters surfaced to Prometheus exporters; not owned here, the
	// observability package wires them.
	droppedEventsTotal atomic.Int64
	panicTotal         atomic.Int64
	autoDisabledTotal  atomic.Int64
}

// NewRegistry constructs an empty Registry. Call `BuildObservers` after
// this to populate it.
func NewRegistry(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	return &Registry{
		logger:        logger,
		detachedCtxFn: defaultDetachedCtxFn,
	}
}

// defaultDetachedCtxFn implements the P1-1 invariant: observer-side ctx
// inherits values from the parent but does NOT inherit cancellation;
// instead it gets its own `maxRequestAge` timeout. If the client
// disconnects mid-stream, the observer goroutine keeps running until
// either OnRequestEnd is called or the timeout fires.
func defaultDetachedCtxFn(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), maxRequestAge)
}

// BuildObservers walks the registration sink and constructs the live
// observer set for this Registry. For each Observer in the sink:
//
//   - if its enable check (provided by the proxy startup wiring) returns
//     false, skip it (INFO log).
//   - else call Build; if Build errors, skip + WARN log (the proxy MUST
//     start regardless — observer errors never block main flow).
//   - else add the resulting StreamingObserver to the active set.
//
// `cfgByName` is a per-observer config block (read from yaml at proxy
// startup); pass nil if no observer takes config.
func (r *Registry) BuildObservers(
	enableCheck func(slug string) bool,
	cfgByName map[string]map[string]any,
) {
	for _, desc := range RegisteredObservers() {
		if enableCheck != nil && !enableCheck(desc.OwnerAppSlug) {
			r.logger.Info("observer: skipped (enable check returned false)",
				"event.name", "proxy.observer.skipped",
				"observer", desc.Name,
				"owner_slug", desc.OwnerAppSlug,
			)
			continue
		}
		cfg := cfgByName[desc.Name]
		impl, err := desc.Build(cfg)
		if err != nil {
			r.logger.Warn("observer: Build failed; observer will be inactive",
				"event.name", "proxy.observer.build_failed",
				"observer", desc.Name,
				"owner_slug", desc.OwnerAppSlug,
				"error.message", err.Error(),
			)
			continue
		}
		ao := &activeObserver{
			descriptor:   desc,
			impl:         impl,
			panicLimiter: newTokenLimiter(panicBudget, panicWindow),
			dumpLimiter:  newTokenLimiter(crashDumpBudget, crashDumpWindow),
		}
		r.observers = append(r.observers, ao)
		r.logger.Info("observer: registered + built",
			"event.name", "proxy.observer.built",
			"observer", desc.Name,
			"owner_slug", desc.OwnerAppSlug,
		)
	}
}

// Active returns the number of currently-active observers, i.e. built
// but not auto-disabled. Used by zero-cost-when-detector-absent tests.
func (r *Registry) Active() int {
	n := 0
	for _, ao := range r.observers {
		if !ao.disabled.Load() {
			n++
		}
	}
	return n
}

// WantsFullPayload reports whether any currently-active observer needs the raw
// request body (the reserved "payload_level=full"). The proxy calls this on the
// hot path to decide whether to buffer + restore the client request body before
// forwarding — a cost it must NOT pay when nobody wants it. Re-evaluated per
// request because an observer's appetite can change at runtime (e.g. an
// enterprise audit observer tracks the live org policy flag).
func (r *Registry) WantsFullPayload() bool {
	for _, ao := range r.observers {
		if ao.disabled.Load() {
			continue
		}
		if fp, ok := ao.impl.(FullPayloadObserver); ok && fp.WantsFullPayload() {
			return true
		}
	}
	return false
}

// Stats returns a snapshot of registry-wide counters. Cheap; safe to
// call from health endpoints.
func (r *Registry) Stats() Stats {
	return Stats{
		DroppedEvents: r.droppedEventsTotal.Load(),
		PanicsTotal:   r.panicTotal.Load(),
		AutoDisabled:  r.autoDisabledTotal.Load(),
	}
}

// Stats is the public snapshot returned by Registry.Stats.
type Stats struct {
	DroppedEvents int64
	PanicsTotal   int64
	AutoDisabled  int64
}

// activeObserver wraps a built StreamingObserver with per-observer
// safety controls. Each request gets its own consumer goroutine
// reading from a per-observer channel; the activeObserver itself is
// shared across requests and holds only safety state.
type activeObserver struct {
	impl         StreamingObserver
	panicLimiter *tokenLimiter // P1-2: 60/min => auto-disable
	dumpLimiter  *tokenLimiter // P1-2: 10/min => skip crash dump
	descriptor   Observer
	disabled     atomic.Bool // flips true after panicLimiter spent
}

// observerEvent is the message type sent to per-(request × observer)
// consumer goroutines. The single struct (kind discriminator) keeps the
// channel typed without a sum-type per kind.
type observerEvent struct {
	eventType string
	payload   []byte // already copied by NotifySSEEvent — observer may retain
	latencyMs int
	kind      eventKind
}

type eventKind uint8

const (
	evStart eventKind = iota
	evSSE
	evEnd
)

// requestState holds per-request fan-out plumbing. Created on
// NotifyStart, removed on NotifyEnd (or maxRequestAge timeout).
type requestState struct {
	ctx      context.Context
	cancel   context.CancelFunc
	channels map[string]chan observerEvent // observer.Name → channel
	req      *RequestContext
}

// ---------------------------------------------------------------------------
// Notify*  — the three entry points called from the App pipeline.
//
// All three are non-blocking. NotifyStart spawns one consumer goroutine
// per active observer (so a request with N observers spawns N goroutines,
// not N × frames). NotifySSEEvent enqueues to those channels with a
// non-blocking select. NotifyEnd closes the channels and the consumers
// drain naturally.
// ---------------------------------------------------------------------------

// NotifyStart begins fan-out for a request. Safe to call with zero
// active observers (returns immediately, no allocation).
//
// `stream` declares which SPEC §1.4.1 stream this request belongs to
// (StreamUserChat / StreamAppPipeline / StreamProbe). Observers whose
// `Streams` declaration does NOT include this value are skipped at this
// stage — no channel is allocated, no consumer goroutine spawned, and
// subsequent NotifySSEEvent / NotifyEnd calls for the same TraceID will
// naturally skip them too (no entry in rs.channels). This is the SPEC
// §1.4-aligned "route to interested observers only" behavior.
//
// MUST be called exactly once before any NotifySSEEvent for the same
// TraceID; calling NotifyStart twice for the same TraceID overwrites
// the previous state silently — that is a bug in the caller, but the
// registry will not crash.
func (r *Registry) NotifyStart(ctx context.Context, stream string, req *RequestContext) {
	if len(r.observers) == 0 || req == nil {
		return
	}
	// Thread the stream onto the request so observers can read it later
	// via req.Stream (the StreamingObserver hooks don't grow their own
	// stream parameter). Safe to mutate here: no consumer goroutine has
	// touched req yet — they start a few lines below in startConsumer.
	req.Stream = stream
	// Per P1-1: observer-side context is detached from the request ctx,
	// so client disconnects don't kill in-flight observer work. It also
	// has its own bounded lifetime (maxRequestAge) to guard against
	// missing NotifyEnd calls.
	obsCtx, cancel := r.detachedCtxFn(ctx)

	rs := &requestState{
		ctx:      obsCtx,
		cancel:   cancel,
		channels: make(map[string]chan observerEvent, len(r.observers)),
		req:      req,
	}
	for _, ao := range r.observers {
		if ao.disabled.Load() {
			continue
		}
		// Per-stream routing: only spawn a consumer for observers that
		// declared interest in this stream. SPEC §1.4.1 vocabulary;
		// declaration enforced at RegisterObserver (must be non-empty,
		// must be valid names).
		if !ao.descriptor.HandlesStream(stream) {
			continue
		}
		ch := make(chan observerEvent, notifyChannelBufferSize)
		rs.channels[ao.descriptor.Name] = ch
		r.startConsumer(ao, ch, rs)
	}
	r.requests.Store(req.TraceID, rs)

	// Send start event without copying payload (none); non-blocking by
	// construction (channels are freshly created with full buffer).
	for _, ch := range rs.channels {
		ch <- observerEvent{kind: evStart}
	}
}

// NotifySSEEvent fan-outs a single SSE frame to all active observers
// for this request. Non-blocking: if any observer's channel is full
// the event is dropped for that observer (only) and a counter is
// incremented.
//
// **P0-1 invariant — payload aliasing**: the `payload` argument is
// copied exactly once here, before fan-out. Observers receive a
// distinct backing array; the drainer's read buffer may be overwritten
// as soon as NotifySSEEvent returns. If you remove this copy, observers
// running asynchronously will see torn frames.
//
// **P0-2 invariant — backpressure**: a slow observer cannot stall the
// drainer. The `select default` case ensures the send is non-blocking;
// a full channel means evidence loss for that observer (visible via
// the dropped-events counter) but the request continues to serve.
func (r *Registry) NotifySSEEvent(ctx context.Context, req *RequestContext, eventType string, payload []byte) {
	if req == nil {
		return
	}
	rsAny, ok := r.requests.Load(req.TraceID)
	if !ok {
		return
	}
	rs, _ := rsAny.(*requestState)
	if len(rs.channels) == 0 {
		return
	}

	// P0-1: one copy here, shared across all observer channels. Doing
	// the copy at the registry boundary (rather than per-observer
	// inside each consumer) keeps memory linear in events, not in
	// (events × observers).
	chunk := append([]byte(nil), payload...)

	ev := observerEvent{kind: evSSE, eventType: eventType, payload: chunk}
	for name, ch := range rs.channels {
		select {
		case ch <- ev:
			// fast path; nothing more to do
		default:
			// P0-2: channel full; drop the frame. We log at DEBUG
			// (rather than WARN) because individual drops are
			// expected under burst load and don't constitute an
			// operational problem unless the cumulative dropped
			// rate is high — that's what the Prometheus counter is
			// for.
			r.droppedEventsTotal.Add(1)
			if r.logger.Enabled(ctx, slog.LevelDebug) {
				r.logger.Debug("observer: SSE event dropped (channel full)",
					"event.name", "proxy.observer.event_dropped",
					"observer", name,
					"trace_id", req.TraceID,
				)
			}
		}
	}
}

// NotifyEnd terminates fan-out for a request. Idempotent (a second call
// for the same TraceID is a no-op). Must be called even on error paths
// so consumer goroutines exit and the request-state map entry is
// removed.
func (r *Registry) NotifyEnd(ctx context.Context, req *RequestContext, totalLatencyMs int) {
	if req == nil {
		return
	}
	rsAny, ok := r.requests.LoadAndDelete(req.TraceID)
	if !ok {
		return
	}
	rs, _ := rsAny.(*requestState)

	// Send end event; if a consumer is slow we still close the channel
	// so it eventually drains. We send non-blocking to keep symmetry
	// with NotifySSEEvent, but allow a single blocking try first — end
	// is the one event we really want to deliver if at all possible.
	for _, ch := range rs.channels {
		ev := observerEvent{kind: evEnd, latencyMs: totalLatencyMs}
		select {
		case ch <- ev:
		default:
			r.droppedEventsTotal.Add(1)
		}
		close(ch)
	}
	// Cancel the detached ctx so any goroutine still doing work inside
	// the observer's OnRequestEnd handler can observe cancellation and
	// give up if it chooses to (e.g., a Reporter waiting on its own
	// internal queue).
	rs.cancel()
}

// startConsumer spawns the single per-(request × observer) consumer
// goroutine. It walks the channel, dispatching evStart / evSSE / evEnd
// to the observer's StreamingObserver methods. Each dispatch is wrapped
// in dispatchOne's `defer recover()` so a panic increments the
// per-observer panic counter, and (above the per-observer budget)
// auto-disables the observer. Subsequent requests stop allocating
// channels for a disabled observer.
//
// The goroutine itself also has a top-level recover so that a panic
// outside the dispatch handler (e.g. accessing a nil rs after a logic
// bug elsewhere) cannot tear down the proxy process. This is the same
// defense-in-depth posture as proxy's internal observability.GoSafe
// helper, kept self-contained here so the observer package stays
// importable by external observer modules without crossing the
// internal/* boundary.
func (r *Registry) startConsumer(ao *activeObserver, ch chan observerEvent, rs *requestState) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				r.panicTotal.Add(1)
				r.logger.Error("observer: consumer goroutine panicked outside dispatch",
					"event.name", "proxy.observer.consumer_panic",
					"error.code", "OBSERVER_CONSUMER_PANIC",
					"observer", ao.descriptor.Name,
					"panic", rec,
					"stack", string(debug.Stack()),
				)
			}
		}()
		for ev := range ch {
			if ao.disabled.Load() {
				continue
			}
			r.dispatchOne(ao, rs, ev)
		}
		// Channel closed (NotifyEnd called). Goroutine exits; the
		// rs entry was already removed from r.requests by NotifyEnd.
	}()
}

// dispatchOne invokes one observer hook, recovering from panic + tracking
// the panic limiter. Inlined cleanly so the consumer loop above stays
// linear.
func (r *Registry) dispatchOne(ao *activeObserver, rs *requestState, ev observerEvent) {
	defer func() {
		if rec := recover(); rec != nil {
			r.panicTotal.Add(1)
			if !ao.panicLimiter.allow() {
				if ao.disabled.CompareAndSwap(false, true) {
					r.autoDisabledTotal.Add(1)
					r.logger.Error("observer: auto-disabled after panic budget exhausted",
						"event.name", "proxy.observer.auto_disabled",
						"error.code", "OBSERVER_PANIC_BUDGET_EXHAUSTED",
						"observer", ao.descriptor.Name,
						"budget_per_minute", panicBudget,
					)
				}
			}
			// Dump policy: rate-limited so a stuck observer cannot
			// flood the dump dir + crash the disk.
			if ao.dumpLimiter.allow() {
				r.logger.Error("observer: panic recovered",
					"event.name", "proxy.observer.panic_recovered",
					"error.code", "OBSERVER_PANIC",
					"observer", ao.descriptor.Name,
					"panic", rec,
				)
			}
		}
	}()
	switch ev.kind {
	case evStart:
		ao.impl.OnRequestStart(rs.ctx, rs.req)
	case evSSE:
		ao.impl.OnSSEEvent(rs.ctx, rs.req, ev.eventType, ev.payload)
	case evEnd:
		ao.impl.OnRequestEnd(rs.ctx, rs.req, ev.latencyMs)
	}
}
