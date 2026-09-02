// Package supervisor implements a single-process dual-generation runtime for
// aikey-proxy.  It keeps the TCP listener open across vault reloads so that
// in-flight requests (including long-running SSE streams) are not interrupted.
//
// Architecture
//
//	Supervisor
//	  ├─ net.Listener  (held for the lifetime of the process)
//	  ├─ active  atomic.Pointer[generation]  (swapped on reload)
//	  └─ reload mutex  (serializes concurrent reload requests)
//
// On Reload():
//  1. Build generation N+1: open vault, load keys, build proxy handler.
//  2. Pass a readiness gate: vault open + key snapshot loaded.
//  3. Atomically swap active pointer → N+1 serves all new requests.
//  4. Write runtime.proxy.loaded_vault_change_seq to vault.db.
//  5. Drain generation N: wait for in-flight requests to finish (with timeout).
//  6. Close N's vault reader and event resources.
//
// If step 2 fails, the swap is never performed and N continues to serve.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/cluster"
	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/observer/conversation_audit"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/apppipe"
	"github.com/AiKeyLabs/aikey-proxy/internal/quota"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/aikey-proxy/pkg/heartbeat"
	"github.com/AiKeyLabs/pkg/providerroutes"
)

func providerBaseURLForProtocol(providerCode, protocolType string) string {
	route, ok := provider.Routes().ByProviderProtocol(providerCode, protocolType)
	if !ok {
		return ""
	}
	return providerroutes.EffectiveUpstream(route)
}

const (
	// ProxyLoadedSeqKey is the vault config key that records which vault
	// change_seq the running proxy has snapshotted.
	ProxyLoadedSeqKey = "runtime.proxy.loaded_vault_change_seq"

	// VaultChangeSeqKey is written by the CLI on every vault write.
	VaultChangeSeqKey = "runtime.vault.change_seq"
	// SourceIdentityKey is the vault config key holding this install's stable
	// delivery-integrity source id (a UUID written by the CLI at vault init).
	// Must match aikey-cli/src/storage.rs SOURCE_IDENTITY_KEY.
	SourceIdentityKey = "runtime.source_identity"
	// seqStateFile is the reserve-ahead high-water-mark file, kept alongside the
	// WAL in the WAL directory so its lifecycle matches the WAL it sequences.
	seqStateFile = "seq.state"

	// drainTimeout is how long the old generation waits for in-flight
	// requests before being forcibly closed.
	drainTimeoutNormal    = 30 * time.Second
	drainTimeoutStreaming = 5 * time.Minute

	// managedKeySyncInterval is how often the background goroutine checks
	// whether the vault's change_seq has advanced and, if so, merges any
	// newly-active managed keys into the live registry without a full reload.
	managedKeySyncInterval = 5 * time.Second
)

// generation holds all per-reload state: vault reader, virtual key registry,
// proxy handler, and event infrastructure.
type generation struct {
	filterHook apphook.FilterTarget // P4 compliance/DLP filter (single child or M-process pool; nil when no filter app is active)
	reporter   *events.Reporter     // usage reporter (nil when collector_url is not configured)
	// standaloneWAL is only populated when this generation created the
	// local WAL writer AND no reporter consumed it — i.e. collector_url is
	// empty. When a reporter is present it owns the WAL and its Close()
	// closes it, so we leave standaloneWAL nil to avoid double-close. This
	// split is what keeps `generation.close()` from leaking file handles
	// on every reload in offline/standalone deployments.
	standaloneWAL   *events.WALWriter
	registry        *vkeys.Registry
	providers       *provider.Registry
	proxy           *proxy.Proxy
	collector       *events.Collector
	eventStore      *events.Store
	drained         chan struct{} // closed when inflight reaches 0 after draining is set
	closeOnce       sync.Once     // close() may be reached by both reload drain_old and Shutdown (bugfix 2026-07-19)
	vault           *vault.Reader
	canary          *events.CanaryProbe // synthetic canary probe (nil when reporter or control_url is not configured)
	contentSeqAlloc *events.SeqAllocator
	// seqAlloc is the delivery-integrity sequence allocator for this generation.
	// Closed in close() so a graceful shutdown shrinks the persisted high-water
	// mark to the actual last-used seq (zero seq burn on the common restart
	// path; only a hard crash leaves a bounded auditable gap). nil when no WAL.
	seqAlloc *events.LaneAllocator
	// Conversation-audit content outbox (enterprise Cluster feature). All nil
	// unless this is a team deployment with a collector + credential — see
	// conversation_audit_wiring.go. Closed in close() like the usage trio:
	// reporter first (flushes its upload loop), then WAL, then seq allocator.
	contentReporter *events.ContentReporter
	contentWAL      *events.ContentWAL
	vaultPath       string
	// Drain tracking: incremented when a request enters Handle, decremented on exit.
	inflight atomic.Int64
	id       int
	draining atomic.Bool
	// signalReporting is applied only when this fully-built generation becomes
	// active. Building a replacement must not reconfigure the process-owned
	// reporter while the current generation is still authoritative.
	signalReporting signalReportingConfig
}

type signalReportingMode uint8

const (
	signalReportingDisabled signalReportingMode = iota
	signalReportingMember
	signalReportingOrg
)

type signalReportingConfig struct {
	mode         signalReportingMode
	controlURL   string
	orgID        string
	serviceToken string
	bearer       func(context.Context) (string, error)
}

func (c signalReportingConfig) apply(p *proxy.Proxy) {
	if p == nil {
		return
	}
	// Every mode is named, and that is the point rather than style: a mode added
	// later would otherwise fall into `default` and silently become "reporting
	// off" — a data-loss default that nothing would flag. With the cases listed,
	// the exhaustive linter fails the build until the new mode is handled.
	switch c.mode {
	case signalReportingMember:
		p.EnableSignalReporting(c.controlURL, c.bearer)
	case signalReportingOrg:
		p.EnableOrgSignalReporting(c.controlURL, c.orgID, c.serviceToken)
	case signalReportingDisabled:
		p.DisableSignalReporting()
	default:
		// Unreachable while the switch above is exhaustive; kept so an
		// out-of-range value cannot leave reporting in an undefined state.
		p.DisableSignalReporting()
	}
}

// ServeHTTP dispatches to the generation's proxy handler, tracking inflight count.
func (g *generation) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.inflight.Add(1)
	defer func() {
		if g.inflight.Add(-1) == 0 && g.draining.Load() {
			select {
			case <-g.drained:
			default:
				close(g.drained)
			}
		}
	}()
	g.proxy.Handle(w, r)
}

// close releases all resources held by this generation. Idempotent (bugfix
// 2026-07-19): Reload's async drain_old goroutine and Shutdown can both reach
// the same generation under a restart-during-reload race — the second run
// panicked in canary.Close ("close of closed channel") and skipped the rest of
// the teardown. Guarding HERE (not just in each member) makes every member's
// release run exactly once regardless of which caller wins.
func (g *generation) close() {
	g.closeOnce.Do(g.closeAll)
}

func (g *generation) closeAll() {
	// Stop the filter child first so it stops consuming stdin/stdout and exits
	// before the rest of the generation tears down. Bounded shutdown — a stuck
	// child must not block the reload drain (the new generation already serves).
	if g.filterHook != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = g.filterHook.Shutdown(ctx)
		cancel()
	}
	// Close canary probe first (it uses the reporter).
	if g.canary != nil {
		g.canary.Close()
	}
	// Close the reporter so its upload loop flushes before the
	// collector and event store are torn down. Reporter owns its WAL when
	// one is attached, so this also closes the shared WAL in the common
	// case.
	if g.reporter != nil {
		_ = g.reporter.Close()
	}
	if g.proxy != nil {
		// The allocation signal reporter is deliberately NOT closed here: it is
		// process-owned so a draining request can publish a late 401/429 after the
		// replacement generation is active. The Supervisor closes it on shutdown.
		// The observer registry remains generation-owned and must be retired.
		// Same reason, different subsystem (2026-08-15): the registry is
		// rebuilt per generation by buildObserverRegistry, and until this call
		// existed nothing ever retired it. rhythm's settings poller (5s tick) and
		// reporter worker pool therefore accumulated one full set per reload —
		// observed as four duplicate `toggle_changed` events from four live
		// pollers. See observer.ClosableObserver.
		g.proxy.StopObservers()
	}
	// Standalone WAL (collector_url empty): generation owns the writer and
	// must close it explicitly, otherwise every reload leaks a file handle
	// on offline-mode deployments. Only non-nil when reporter is nil.
	if g.standaloneWAL != nil {
		_ = g.standaloneWAL.Close()
	}
	// Close the seq allocator AFTER the WAL is flushed: it shrinks the persisted
	// high-water mark to the actual last-used seq, so a graceful restart resumes
	// exactly there with zero burned (known-loss) seqs.
	if g.seqAlloc != nil {
		_ = g.seqAlloc.Close()
	}
	// Conversation-audit content outbox: same order as the usage trio — reporter
	// first (its upload loop does a final flush on Close), then WAL, then the
	// content seq allocator (shrinks its high-water mark like usage's).
	if g.contentReporter != nil {
		_ = g.contentReporter.Close()
	}
	if g.contentWAL != nil {
		_ = g.contentWAL.Close()
	}
	if g.contentSeqAlloc != nil {
		_ = g.contentSeqAlloc.Close()
	}
	if g.collector != nil {
		_ = g.collector.Close()
	}
	if g.eventStore != nil {
		_ = g.eventStore.Close()
	}
	if g.vault != nil {
		_ = g.vault.Close()
	}
}

// drain signals this generation to stop accepting new requests, then waits
// until all in-flight requests complete or the timeout is reached.
func (g *generation) drain(timeout time.Duration, reloadID string) {
	g.draining.Store(true)
	inflight := g.inflight.Load()

	slog.Info("generation draining",
		"event.name", observability.EventProxyGenerationDraining,
		"generation_id", g.id,
		"reload_id", reloadID,
		"inflight", inflight,
	)

	if inflight == 0 {
		select {
		case <-g.drained:
		default:
			close(g.drained)
		}
	}

	select {
	case <-g.drained:
		slog.Info("generation drained",
			"event.name", observability.EventProxyGenerationDrained,
			"generation_id", g.id,
			"reload_id", reloadID,
		)
	case <-time.After(timeout):
		slog.Warn("generation drain timed out, forcing close",
			"event.name", observability.EventProxyGenerationDrainTimeout,
			"generation_id", g.id,
			"reload_id", reloadID,
			"inflight", g.inflight.Load(),
		)
	}
}

// Supervisor manages the proxy lifecycle and exposes the data-plane handler.
type Supervisor struct {
	startedAt time.Time
	// transport is the optional upstream-proxy RoundTripper applied to every
	// generation's proxy (nil = default). atomic.Pointer so an egress hot-swap
	// (SetTransport, 2026-06-30) can't race the gen-build read in applyToProxy.
	transport atomic.Pointer[transportBox]
	// oauthEgressOverride is the opt-in escape hatch (2026-07-19), supervisor-scoped
	// so it SURVIVES reloads/5s syncs (like transport/broker): buildGeneration
	// re-applies it to every new generation's proxy. Default false → coexist
	// unchanged. Set via SetOAuthEgressOverride (from the /admin toggle).
	oauthEgressOverride atomic.Bool
	// pathHealth is supervisor-scoped live path reachability. Every generation
	// receives this same pointer, so a reload cannot erase an open breaker or its
	// recovery opportunity and hot network/egress changes can wake it immediately.
	pathHealth *proxy.ProviderPathHealthManager
	// oauthPoolRuntime is the single in-memory truth for OAuth-pool cooldowns,
	// exact-token tombstones, and allocation-signal pending work. Generations
	// share it; only Shutdown closes it.
	oauthPoolRuntime *proxy.OAuthPoolRuntimeState
	// signalRefreshToken supplies the process-owned reporter without capturing a
	// generation-owned vault Reader. It opens the currently activated vault only
	// when teamCredentialSource needs to rebuild its credential.
	signalRefreshToken *runtimeRefreshTokenSource
	// ctx / cancel bound the lifetime of all detached upstream calls.
	// Canceled in Shutdown() to stop any in-flight upstream requests.
	ctx    context.Context
	broker proxy.OAuthBroker // OAuth broker (set via SetBroker); nil = OAuth disabled
	// lastFilterSig is the signature (sorted slug list) of the filter apps the
	// active generation was built with. syncManagedKeys compares it to the
	// vault's current filter-app set on each change_seq advance; a difference
	// means a filter app was enabled/disabled (e.g. the cluster daemon toggling
	// compliance) — which the lightweight registry-only rebuild does NOT pick up
	// (the filter child lives on the generation, not the registry). On a change
	// we trigger a full Reload so the filter hook re-installs. Without this,
	// daemon-driven compliance enablement only took effect on a manual
	// /admin/reload (gap found by the 2026-06-05 cluster E2E).
	lastFilterSig atomic.Pointer[string]
	quotaSnapshot *quota.Snapshot
	active        atomic.Pointer[generation]
	cancel        context.CancelFunc
	cfg           *config.Config
	// lastQuotaSig is the signature of the last quota policy this node pulled from
	// the master (C′ 2026-06-17). pollQuotaPolicy uses it to write quota_rules_cache
	// + Reload ONLY when the policy actually changed — so an admin's limit edit
	// takes effect within the 60s poll WITHOUT the employee running any command,
	// and steady state adds no churn. Mirrors lastFilterSig / masterCompliance.
	lastQuotaSig atomic.Pointer[string]
	// lastGroupRuntimeSig is the signature (raw response body) of the last group
	// runtime this node pulled (N7c-2). pollGroupRuntime rewrites group_runtime +
	// Reloads ONLY when the material actually changed (a token refreshed), so a
	// 60s poll over unchanged tokens adds no churn. Mirrors lastQuotaSig.
	lastGroupRuntimeSig atomic.Pointer[string]
	// currentRoutedRestampKick bridges reactive whole-account cooldown changes
	// from the request hot path to the display-only group_runtime projection.
	// Capacity 1 intentionally coalesces an error burst; the callback never blocks
	// and one worker performs the SQLite RMW off-path. The mutex serializes every
	// group_runtime projection writer: reactive/override restamps and the 60s
	// material sync, preventing an older poll snapshot from reverting a 429 switch.
	currentRoutedRestampKick chan struct{}
	currentRoutedRestampMu   sync.Mutex
	// routingOverrides is the allocation engine's seat→account routing-override
	// cache (I-side §6.5). Supervisor-scoped (not per-generation) so a reload never
	// loses it — the same instance is injected into every Proxy. Populated by
	// pollRoutingOverrides; read on the group-route hot path to redirect a seat off
	// an unhealthy account. nil-safe everywhere → empty means "use the local pick".
	routingOverrides *proxy.RoutingOverrideCache
	// lastClusterRoutingSig tracks the complete daemon-managed assignment
	// snapshot, including rows whose explicit pending state is persisted as an
	// empty column. routing_version alone cannot observe such removals when a
	// sibling route still carries the previous maximum version.
	lastClusterRoutingSig atomic.Pointer[string]
	// fallbackPolicy is the upstream-fallback threshold cache (P0a, task 1b.4).
	// Supervisor-scoped like routingOverrides so a generation reload never loses
	// it — keep-last-known is the point: a control-plane blip must not re-time
	// requests across the fleet.
	fallbackPolicy *proxy.FallbackPolicyCache
	// licensePlane is the deployment's forwarding gate (2026-08-27).
	// Supervisor-scoped for the same reason as fallbackPolicy: a generation
	// reload must not lose it. Nothing REFUSES on it yet — this change makes the
	// verdict observable; the request path consumes it separately.
	licensePlane *proxy.LicensePlaneCache
	// lastRoutingMismatchVersion throttles the proxy.routing_override.format_mismatch
	// WARN (non-empty routes, zero matching a local (seat,group)) to once per
	// routing_version — the 60s ticker would otherwise repeat it every cycle.
	lastRoutingMismatchVersion atomic.Int64
	// railset drives the SyncRail control-plane sync rails (railset.go,
	// 2026-07-03): routing_override + group_runtime in Phase 1. Supervisor-scoped
	// so Reload can kick an immediate re-sync and /status can snapshot rail health.
	railset *railSet
	// teamCred is the shared on-demand team account-JWT source for the rails —
	// rebuilt whenever the control URL changes or a refresh fails (the fix for the
	// 2026-07-03 "credential baked at start with a stale URL" incident).
	teamCred *teamCredentialSource
	// revokedVKIDs holds the virtual-key ids the control plane has stopped
	// honoring, as of the key_revocation rail's last successful poll. Read on
	// every route rebuild (buildManagedRoutes), written only by that rail.
	//
	// 🔴 A nil pointer means "the rail has never successfully answered", which is
	// deliberately indistinguishable from "nothing is revoked": both serve what
	// the vault holds. Failing the other way — refusing every team key while the
	// control plane is unreachable — would turn a master outage into a fleet-wide
	// outage, which is the opposite of the offline-first rule every other rail
	// follows (railset.go §2.3).
	revokedVKIDs atomic.Pointer[map[string]bool]
	// lastSyncVersion is the account sync_version this proxy has already resolved
	// into revokedVKIDs. The rail skips the (heavier) snapshot fetch while the
	// server's counter is unchanged.
	lastSyncVersion atomic.Int64
	// quotaHeartbeat is the traffic-independent server-reachability probe behind
	// budget-mode staleness (D-U7/P9). nil unless enforce_mode=budget AND a
	// collector URL is configured — so the default availability path (and Personal)
	// adds NO periodic server call (offline-first preserved). The 5s sync copies its
	// LastOKAt into the snapshot for budgetStale.
	quotaHeartbeat    *heartbeat.Probe
	quotaCounter      *quota.Counter
	configPath        string // path to the YAML config file, re-read on reload
	password          string
	version           string // build version, passed to proxy for audit metadata
	convAuditMaxBytes atomic.Int64
	genID             atomic.Int64
	reloadMu          sync.Mutex // serialize concurrent reload requests
	// runtimeStateMu serializes the short generation-activation boundary with
	// hot updates of supervisor-owned runtime state. buildGeneration deliberately
	// stays outside this lock: only applying the latest transport/override/broker
	// snapshot and swapping active must be atomic. Without this fence, a generation
	// built from an older snapshot can become active after a Settings PUT returned
	// 200 and silently restore direct/old egress.
	runtimeStateMu sync.Mutex
	// convAuditEnabled / convAuditMaxBytes: org-level conversation-audit capture
	// switch + per-turn content cap, polled from the control backend by
	// pollConversationAuditPolicy (mirrors masterCompliance, v1.0.1-alpha.2).
	// Default OFF. The forward-path capture hook reads these atomics per request —
	// a flip needs NO spawn/Reload (unlike compliance), it just gates capture.
	convAuditEnabled atomic.Bool
	// masterCompliance is the org-level compliance master switch polled from the
	// control backend (G3). The supervisor is the LIFECYCLE owner of the
	// compliance detector: the app pulls its own packs, but whether it runs at
	// all is decided here. true → force-spawn the detector even when the user's
	// local filter_stages is NULL (master mandate); the user's local toggle still
	// governs when this is false. Polled by pollComplianceMasterPolicy.
	masterCompliance atomic.Bool
	// masterPasswordTierAdvanced mirrors masterPrivacyTier for the password
	// lane (阶段8/合规密码档分级): true ⇒ the org forces the detector's
	// CREDENTIAL_PASSWORD lane to advanced (full enforcement), baked into the
	// child env at spawn; false ⇒ no force, the machine's own level governs.
	// Polled by pollComplianceMasterPolicy from the same policy endpoint.
	masterPasswordTierAdvanced atomic.Bool
	// masterPrivacyTier is the org-level compliance PRIVACY TIER polled from the
	// same endpoint as masterCompliance (1 metadata / 2 + masked snippet / 3 +
	// RAW snippet). It decides how much of this user's own text the detector may
	// attach to the compliance events it uploads to the team server.
	//
	// 🔴 THIS IS THE ONLY WAY THAT DECISION CAN ARRIVE. There is deliberately no
	// vault column, no config key and no env override by which the person whose
	// prompts these are could raise it — the whole design rests on the
	// authorisation being the ORGANISATION's, held on the org's own server. The
	// value is passed to the detector as AIKEY_COMPLIANCE_PRIVACY_TIER at spawn
	// (installFilterHook) and re-checked by the master at ingest.
	//
	// Default 1: the zero value of an Int64 clamps to metadata-only, so a node
	// that has never reached its policy, or reached it and failed to parse it,
	// sends no content. Unlike masterCompliance a change needs a Reload — the
	// value is baked into a child process's environment at spawn.
	masterPrivacyTier atomic.Int64
	// Enterprise quota (Phase 2 Stage 2 — design §0.5/§5.2). Snapshot + counter
	// live on the supervisor (not per-generation) so the counter accumulates
	// continuously across 5s syncs and /admin/reload; the snapshot is gen-swapped
	// on each vault-seq advance. quotaEnabled gates LOADING only (off = the
	// rule-distribution rail is fully bypassed, proxy == pre-quota behavior).
	// Stage 2 only loads + counts; request interception is Stage 3.
	quotaEnabled bool
	// quotaIncrementSeeded guards the one-time restore of persisted local
	// increments (quota_local_usage, P0) into the counter at startup. Seeding is a
	// SET before any accrual; re-running would clobber in-flight increments, so it
	// fires exactly once (first reloadQuotaSnapshot, in buildGeneration, before
	// serving). Later reloads only re-seed baselines.
	quotaIncrementSeeded bool
}

// VaultReader opens a vault connection for use by the OAuth broker.
// Returns nil if the vault cannot be opened (broker should degrade gracefully).
func (s *Supervisor) VaultReader() *vault.Reader {
	r, err := vault.Open(s.cfg.Vault.Path, s.password)
	if err != nil {
		return nil
	}
	return r
}

// New creates a Supervisor, starts the initial generation, and launches the
// background managed-key sync goroutine.
// configPath is the filesystem path to aikey-proxy.yaml; it is re-read on
// every Reload so that changes to collector_url, collector_token, etc. take
// effect without a full stop+start cycle.
func New(cfg *config.Config, configPath, password, version string) (*Supervisor, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Supervisor{
		cfg:              cfg,
		configPath:       configPath,
		password:         password,
		version:          version,
		startedAt:        time.Now(),
		ctx:              ctx,
		cancel:           cancel,
		quotaEnabled:     quotaEnabledFromEnv(),
		quotaSnapshot:    quota.NewSnapshot(),
		quotaCounter:     quota.NewCounter(),
		routingOverrides: proxy.NewRoutingOverrideCache(),
		// P0a task 1b.4/1b.7. Seeded with the ONE local-yaml layer that already
		// existed (`providers.<name>.timeout`); the other four thresholds
		// deliberately have no local knob — see LocalOverrides for why widening it
		// would recreate the four-source base_url drift.
		fallbackPolicy:           proxy.NewFallbackPolicyCache(localAttemptTimeoutMs(cfg)),
		licensePlane:             proxy.NewLicensePlaneCache(),
		pathHealth:               proxy.NewProviderPathHealthManager(),
		oauthPoolRuntime:         proxy.NewOAuthPoolRuntimeState(),
		signalRefreshToken:       newRuntimeRefreshTokenSource(cfg.Vault.Path, password),
		teamCred:                 &teamCredentialSource{},
		currentRoutedRestampKick: make(chan struct{}, 1),
	}
	// 🔴 A sixth FOLLOWER, not a sixth loop (task 1b.4). railSpec.interval is
	// per-rail, so declaring 10s here leaves the other five untouched.
	// key_revocation (2026-08-26) rides the same framework so a control-plane
	// suspension reaches a running proxy within one cycle instead of waiting for
	// the member to type an aikey command (which may never happen).
	// license_plane (2026-08-27) is the seventh rail. It carries the deployment's
	// forwarding gate, which the control plane had been computing and serving all
	// along with nothing on this side reading it — see license_plane_rail.go.
	// licenseRails() is build-tag split: the licensing rails in a normal build,
	// none in a -tags aikey_license_off build (see license_rail_off.go — the gate
	// they feed is compiled out, so a running rail could only log 404s forever).
	s.railset = newRailSet(append([]railSpec{s.groupRuntimeRail(), s.routingOverrideRail(), s.fallbackPolicyRail(), s.keyRevocationRail()}, s.licenseRails()...)...)
	gen, err := s.buildGeneration()
	if err != nil {
		_ = s.oauthPoolRuntime.Shutdown()
		return nil, fmt.Errorf("initial generation failed: %w", err)
	}
	s.activateGeneration(gen)
	// Seed the quota change-signal from the quota_rules_cache the initial
	// generation just loaded, so the FIRST quota poll after boot is a no-op when
	// the master's rules are unchanged — instead of always detecting a phantom
	// "changed" against a nil baseline and forcing a reload. Stateless: the
	// baseline is reconstructed from the already-persisted cache every boot,
	// nothing new is persisted. Bugfix 20260725-proxy-startup-reload-storm-*.
	s.seedQuotaSig(gen)
	observability.GoSafe("supervisor.current_routed_restamp_loop", observability.Isolated, s.currentRoutedRestampLoop)
	// Re-project any cooldowns hydrated from pool-cooldown.json. buildGeneration
	// creates the Proxy before it becomes active, so the post-swap kick is the
	// first point at which restampCurrentRouted can read the correct generation.
	s.requestCurrentRoutedRestamp()
	slog.Info("supervisor started",
		"generation_id", gen.id,
	)
	// Fatal: silent death of the managed-key sync loop means server-side
	// updates to provider keys never reach this proxy. That's a
	// long-lived correctness/security risk, not a per-request issue.
	observability.GoSafe("supervisor.managed_key_sync_loop", observability.Fatal, s.managedKeySyncLoop)

	// Local usage-data retention: WAL archive/expiry + usage_events prune
	// (费用小票 §11 design; 2026-06-10 decision (a)). Process-level (not
	// per-generation) because the WAL dir and policy never change across
	// reloads; the store handle DOES, so the loop resolves it via s.active
	// at each sweep. Isolated: retention is a bypass — a panic here must
	// never affect forwarding. Negative wal_retention_days disables.
	if s.cfg.Events.WALDir != "" && s.cfg.Events.WALRetentionDays > 0 {
		rcfg := events.RetentionConfig{
			WALDir:        s.cfg.Events.WALDir,
			RetentionDays: s.cfg.Events.WALRetentionDays,
			ArchiveDays:   s.cfg.Events.WALArchiveDays,
		}
		observability.GoSafe("supervisor.usage_retention_loop", observability.Isolated, func() {
			events.RetentionLoop(s.ctx, rcfg, func() *events.Store {
				if g := s.active.Load(); g != nil {
					return g.eventStore
				}
				return nil
			})
		})
	}

	// Conversation audit (v1.0.1-alpha.2): poll the org-level capture switch so an
	// enterprise can turn employee conversation capture on from the control backend.
	// No-op when no team/org (Personal). A flip just gates the forward-path capture
	// hook (reads the atomic) — no detector to spawn, unlike compliance. Kept here
	// (started in New) precisely because it never triggers a Reload, so it cannot
	// contribute to the pre-serve reload storm the way compliance/quota/group do.
	observability.GoSafe("supervisor.conversation_audit_policy_poll", observability.Isolated, func() { s.pollConversationAuditPolicy(s.ctx) })

	// The master-policy pollers whose first sync CAN trigger a Reload — compliance
	// mandate, quota rules, and the group_runtime / routing-override rails — are
	// deliberately NOT started here. They are launched by StartPolicyPollers()
	// AFTER the HTTP server is serving. See that method for why (pre-serve reload
	// storm vs the CLI's 5s health gate). Bugfix
	// 20260725-proxy-startup-reload-storm-5s-health-fail.

	// Control-plane self-heal, Stage 2 (2026-07-01): proactively rebuild the
	// control-plane client the moment the host's network changes (WiFi switch /
	// tether / interface up-down), so control-plane calls to master dial clean
	// without waiting for a failure. Dependency-free (net.Interfaces fingerprint).
	// Isolated + cheap: a 20s poll; a panic here must never touch the data path.
	// See netmon.go / selfheal.go.
	observability.GoSafe("supervisor.net_change_monitor", observability.Isolated, func() {
		runNetChangeMonitor(s.ctx, s.pathHealth.NotifyInputsChanged)
	})

	// Cluster mode (V3c): register this node with the hub name service + heartbeat
	// so clients discover it via /cluster/resolve. Inert for non-cluster proxies —
	// Personal/Trial never set Cluster.Enabled, so this is a no-op there. Isolated
	// (not Fatal): a registrar panic must NOT kill the data path; the proxy keeps
	// serving locally even if the hub is unreachable.
	if s.cfg.Cluster.Enabled {
		reg := cluster.NewRegistrar(
			s.cfg.Cluster.HubURL,
			s.cfg.Cluster.NodeID,
			s.cfg.Cluster.NodeAddr,
			s.cfg.Cluster.Weight,
			s.cfg.Cluster.ServiceToken,
		)
		// Health piggyback (P0-B): forward the co-located cluster-daemon's
		// status file + proxy-own metrics + usage-pipeline canary verdict on
		// every heartbeat so node health is externally readable. Pure
		// side-channel: collection failures degrade to a bare heartbeat,
		// never affect the data path. The canary adapter must return an
		// untyped nil when the probe is disabled — boxing a typed nil
		// pointer into `any` would serialize as JSON null instead of
		// omitting the section.
		canaryFn := func() any {
			if cr := s.CanaryResult(); cr != nil {
				return cr
			}
			return nil
		}
		// Phase-4 runtime metrics: upstream forward counters (cumulative; hub
		// windows them) + usage-reporter backlog/stall. All cheap in-process
		// reads; nil-safe (reporter absent on a collector-less node).
		metricsFn := func() cluster.RuntimeMetrics {
			rm := cluster.RuntimeMetrics{
				Requests:             s.TotalRequests(),
				Errors:               s.TotalErrors(),
				ReportLastUploadAgeS: -1,
			}
			if m := s.ReporterMetrics(); m != nil {
				rm.ReportConsecutiveFailures = m.ConsecutiveFailures
				rm.ReportTerminalFails = m.TerminalFailCount
				if m.LastUploadAt > 0 {
					age := time.Now().Unix() - int64(m.LastUploadAt)/1000
					if age < 0 {
						age = 0
					}
					rm.ReportLastUploadAgeS = age
				}
			}
			return rm
		}
		poolRoutingFn := func() any {
			if !vkeys.OauthGroupRoutingEnabled() {
				return nil
			}
			type cooledAccount struct {
				AccountID       string `json:"account_id"`
				OAuthGroupID    string `json:"oauth_group_id,omitempty"`
				SeatID          string `json:"seat_id,omitempty"`
				CooldownSeconds int    `json:"cooldown_seconds"`
				CooldownUntil   int64  `json:"cooldown_until"`
				RouteStatus     string `json:"route_status,omitempty"`
				RouteRetryAt    int64  `json:"route_retry_at,omitempty"`
				ErrorCode       string `json:"error_code,omitempty"`
			}
			remaining := s.PoolCooldownSnapshot()
			states := s.PoolRouteStateSnapshot()
			accounts := make([]cooledAccount, 0, len(remaining))
			now := time.Now().Unix()
			for id, secs := range remaining {
				item := cooledAccount{AccountID: id, CooldownSeconds: secs, CooldownUntil: now + int64(secs)}
				if state, ok := states[id]; ok {
					item.RouteStatus = state.Status
					item.RouteRetryAt = state.RetryAt
					item.ErrorCode = state.ErrorCode
				}
				accounts = append(accounts, item)
			}
			for _, state := range s.PoolAuthFailureSnapshot() {
				accounts = append(accounts, cooledAccount{
					AccountID: state.AccountID, OAuthGroupID: state.OAuthGroupID,
					SeatID: state.SeatID, RouteStatus: "auth_failed",
				})
			}
			sort.Slice(accounts, func(i, j int) bool {
				if accounts[i].AccountID != accounts[j].AccountID {
					return accounts[i].AccountID < accounts[j].AccountID
				}
				if accounts[i].OAuthGroupID != accounts[j].OAuthGroupID {
					return accounts[i].OAuthGroupID < accounts[j].OAuthGroupID
				}
				return accounts[i].SeatID < accounts[j].SeatID
			})
			// assignment_routing_version: the engine-assignment revision this
			// worker is SERVING (override cache). The control-side cluster
			// health compares it against the ledger's max routing_version —
			// the P3 "projection stale" yellow light (方案 20260819 D4): a
			// worker whose daemon/apply chain stalls stops advancing this
			// number while control's keeps moving.
			return struct {
				Enabled                  bool            `json:"enabled"`
				AssignmentRoutingVersion int64           `json:"assignment_routing_version,omitempty"`
				CooledAccounts           []cooledAccount `json:"cooled_accounts,omitempty"`
			}{Enabled: true, AssignmentRoutingVersion: s.routingOverrides.Version(), CooledAccounts: accounts}
		}
		reg.SetHealthSource(cluster.NodeHealthSource(s.cfg.Vault.Path, s.version, time.Now(), canaryFn, metricsFn, poolRoutingFn))
		observability.GoSafe("supervisor.cluster_registrar", observability.Isolated, func() { reg.Run(s.ctx) })
		slog.Info("cluster mode enabled", "node_id", s.cfg.Cluster.NodeID, "hub", s.cfg.Cluster.HubURL)
	}

	// Budget-mode quota staleness heartbeat (D-U7/P9). ONLY started when
	// enforce_mode=budget AND a collector URL exists — so the default availability
	// path and Personal add no periodic server call (offline-first preserved).
	// Isolated: a probe panic must never kill the data path. See startQuotaHeartbeat.
	s.startQuotaHeartbeat()

	return s, nil
}

// StartPolicyPollers launches the master-policy pollers whose first sync can
// trigger a generation Reload: the compliance mandate switch, the quota rules,
// and the group_runtime / routing-override rails.
//
// Why they are NOT started in New(): their immediate first sync runs concurrently
// with the pre-serve setup (broker + credential warm-up), and on a mandate org
// each triggered reload re-spawns the ai-compliance-detector child — a ~3s+ cold
// start (CRF models + AC lexicons). Three such reloads at boot starve the main
// goroutine before it reaches http.Serve, so the CLI's 5s health probe on /health
// kills the proxy before it ever listens (found 2026-07-25: every restart-personal
// failed with "did not become healthy in 5s"). Starting them AFTER the server is
// serving moves that work off the startup-critical path: /health (admin mux, never
// gated by the data-path filter) answers immediately and the pollers converge in
// the background. The conversation-audit poller stays in New() because it never
// triggers a Reload. Call exactly once, right after the serve goroutine launches.
// Bugfix 20260725-proxy-startup-reload-storm-5s-health-fail.
func (s *Supervisor) StartPolicyPollers() {
	// G3: org-level compliance master switch (force-spawn the detector regardless
	// of the user's local toggle). No-op when no team/org (Personal).
	observability.GoSafe("supervisor.compliance_policy_poll", observability.Isolated, func() { s.pollComplianceMasterPolicy(s.ctx) })
	// C′ (2026-06-17): the org's quota policy so an admin's limit edit on the master
	// takes effect within 60s without the employee running any aikey command. No-op
	// when no team/org, no active seats, or quota disabled.
	observability.GoSafe("supervisor.quota_policy_poll", observability.Isolated, func() { s.pollQuotaPolicy(s.ctx) })
	// SyncRail (2026-07-03): group_runtime (N7c-2 channel ③ material) + routing_override
	// (I-side §6.5 engine assignments) rails. One GoSafe/Isolated goroutine per rail.
	s.railset.start(s)
}

// seedQuotaSig primes lastQuotaSig from the quota_rules_cache that the initial
// generation already loaded (reloadQuotaSnapshot → quota.LoadSubjects), computing
// the signal with the SAME function the poller uses (quotaSubjectsSig). So the
// first quota poll after boot is a no-op when the master's rules are unchanged
// since last run, instead of always detecting a phantom "changed" against a nil
// baseline and forcing a reload. Stateless — the baseline is rebuilt from the
// already-persisted cache each boot; nothing new is persisted. No-op (leaves the
// baseline nil, i.e. legacy behavior) when quota is off or the cache is
// unreadable. Bugfix 20260725-proxy-startup-reload-storm-5s-health-fail.
func (s *Supervisor) seedQuotaSig(gen *generation) {
	if !s.quotaEnabled || gen == nil || gen.vault == nil {
		return
	}
	subjects, err := quota.LoadPolicySubjects(gen.vault.DB())
	if err != nil {
		slog.Warn("quota.sig_seed.load_failed",
			"event.name", "proxy.quota.sig_seed_failed", "error", err.Error())
		return
	}
	sig, err := quotaSubjectsSig(subjects)
	if err != nil {
		slog.Warn("quota.sig_seed.marshal_failed",
			"event.name", "proxy.quota.sig_seed_failed", "error", err.Error())
		return
	}
	s.lastQuotaSig.Store(&sig)
}

// startQuotaHeartbeat wires the traffic-independent server-reachability probe for
// budget-mode quota staleness (D-U7/P9). No-op unless quota is enabled, enforce_mode
// is budget, and a collector URL is configured — keeping availability-mode and
// Personal deployments free of any new periodic server contact (offline-first).
//
// Probe target: the collector's cheap unauthenticated GET /health (the collector
// is the source of the usd baseline whose freshness budget mode guards). Cadence:
// maxStaleness/3 clamped to [30s, 120s] so a single transient miss can't trip a
// fail-closed (≈3 consecutive misses needed). The 5s managed-key sync copies the
// probe's LastOKAt into the snapshot for budgetStale.
func (s *Supervisor) startQuotaHeartbeat() {
	if !s.quotaEnabled {
		return
	}
	budget, maxStaleness := quotaBudgetModeFromEnv()
	if !budget {
		return
	}
	base := s.cfg.Events.CollectorURL
	if base == "" {
		base = s.cfg.Events.ControlURL
	}
	if base == "" {
		slog.Warn("quota budget mode on but no collector/control URL — staleness heartbeat disabled (budget fail-closed cannot trigger)",
			"event.name", "proxy.quota.heartbeat_no_url")
		return
	}
	healthURL := strings.TrimRight(base, "/") + "/health"
	interval := maxStaleness / 3
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	if interval > 120*time.Second {
		interval = 120 * time.Second
	}
	client := httpx.NewDirectClient(5 * time.Second)
	s.quotaHeartbeat = heartbeat.New(interval, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, http.NoBody)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("collector health: %d", resp.StatusCode)
		}
		return nil
	})
	observability.GoSafe("supervisor.quota_heartbeat", observability.Isolated, func() { s.quotaHeartbeat.Run(s.ctx) })
	slog.Info("quota budget-mode staleness heartbeat started",
		"event.name", "proxy.quota.heartbeat_started",
		"health_url", healthURL, "interval", interval, "max_staleness", maxStaleness)
}

// generationRuntimeTarget is the complete supervisor-owned runtime state that a
// Proxy generation must inherit at activation. Keeping every setter behind
// one interface makes omission visible in the activation regression test.
type generationRuntimeTarget interface {
	SetTransport(http.RoundTripper)
	SetOAuthEgressOverride(bool)
	SetBroker(proxy.OAuthBroker)
	SetProviderPathHealthManager(*proxy.ProviderPathHealthManager)
}

// applyRuntimeState installs the latest supervisor-owned runtime state on target.
// The caller must hold runtimeStateMu whenever target can become active.
func (s *Supervisor) applyRuntimeState(target generationRuntimeTarget) {
	var transport http.RoundTripper
	if box := s.transport.Load(); box != nil {
		transport = box.rt
	}
	target.SetTransport(transport)
	target.SetOAuthEgressOverride(s.oauthEgressOverride.Load())
	target.SetBroker(s.broker)
	target.SetProviderPathHealthManager(s.pathHealth)
}

// activateGeneration is the only active-generation swap path. A concurrent hot
// update either completes first and is copied into newGen, or completes second
// and updates newGen after it becomes active; neither ordering can lose state.
func (s *Supervisor) activateGeneration(newGen *generation) {
	s.runtimeStateMu.Lock()
	defer s.runtimeStateMu.Unlock()
	s.applyRuntimeState(newGen.proxy)
	if s.signalRefreshToken != nil {
		s.signalRefreshToken.update(newGen.vaultPath, s.password)
	}
	newGen.signalReporting.apply(newGen.proxy)
	s.active.Store(newGen)
}

// SetBroker sets the OAuth broker for all proxy generations.
func (s *Supervisor) SetBroker(b proxy.OAuthBroker) {
	s.runtimeStateMu.Lock()
	defer s.runtimeStateMu.Unlock()
	s.broker = b
	if gen := s.active.Load(); gen != nil {
		gen.proxy.SetBroker(b)
	}
}

// SetTransport hot-swaps the outbound RoundTripper used by the active generation
// and guarantees that a concurrently activating generation cannot restore the
// previous transport after this call returns.
func (s *Supervisor) SetTransport(t http.RoundTripper) {
	s.runtimeStateMu.Lock()
	defer s.runtimeStateMu.Unlock()
	s.transport.Store(&transportBox{rt: t})
	if gen := s.active.Load(); gen != nil {
		gen.proxy.SetTransport(t)
	}
	if s.pathHealth != nil {
		s.pathHealth.NotifyInputsChanged()
	}
}

// SetOAuthEgressOverride flips the opt-in escape hatch (2026-07-19) across all
// generations. Stores it supervisor-scoped (so activateGeneration applies it to
// reloads) AND hot-applies to the running generation — same pattern as
// SetTransport. Node-local, default false.
func (s *Supervisor) SetOAuthEgressOverride(on bool) {
	s.runtimeStateMu.Lock()
	defer s.runtimeStateMu.Unlock()
	changed := s.oauthEgressOverride.Swap(on) != on
	if gen := s.active.Load(); gen != nil {
		gen.proxy.SetOAuthEgressOverride(on)
	}
	if changed && s.pathHealth != nil {
		s.pathHealth.NotifyInputsChanged()
	}
}

// OAuthEgressOverride reports the current escape-hatch state (for GET /admin).
func (s *Supervisor) OAuthEgressOverride() bool { return s.oauthEgressOverride.Load() }

// transportBox boxes the RoundTripper so it can live in an atomic.Pointer (atomics
// can't hold an interface value directly). nil rt = use the default transport.
type transportBox struct{ rt http.RoundTripper }

// managedKeySyncLoop runs in a background goroutine and periodically merges
// newly-active managed keys into the live registry without a full reload.
//
// It compares runtime.vault.change_seq against the seq last recorded by the
// active generation. When they differ it reads managed_virtual_keys_cache from
// the vault and calls registry.Merge with any new or updated active routes.
// This means aikey key use takes effect within managedKeySyncInterval without
// requiring aikey proxy restart or POST /admin/reload.
func (s *Supervisor) managedKeySyncLoop() {
	ticker := time.NewTicker(managedKeySyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.syncManagedKeys()
		}
	}
}

// healFilterStubIfResolvable clears a fail-loud 501 latch once the binary it
// was waiting for exists. It reloads (rather than flipping the flag) because
// the filter child lives on the generation: only a rebuild can spawn it.
//
// Scope is deliberately narrow — it acts ONLY when the proxy is currently
// latched, and only for the binary-missing causes. A spawn failure is left
// alone: retrying a child that just failed to start, every five seconds,
// forever, is a crash loop, and its cure (fix the binary, reinstall) does go
// through a declaration change or a restart.
func (s *Supervisor) healFilterStubIfResolvable() {
	s.healFilterStubWithReload(s.Reload)
}

// healFilterStubWithReload is the testable core: the reload is a parameter so a
// test can assert WHETHER it was called (the whole point of the fix) without
// standing up a real generation rebuild.
func (s *Supervisor) healFilterStubWithReload(reload func(context.Context) error) {
	gen := s.active.Load()
	if gen == nil || gen.proxy == nil {
		return
	}
	cause := gen.proxy.FilterStub501Cause()
	if cause == nil {
		return // serving normally: no stat, no work
	}
	switch cause.Reason {
	case proxy.FilterStubReasonBinaryMissing, proxy.FilterStubReasonMandateNotInstalled:
	default:
		return // spawn failures do not self-heal on a timer (see above)
	}
	if bin, _ := resolveAppBinary(s.appsDir(), []string{slugOrDetector(cause.Slug)}); bin == "" {
		return // still missing
	}
	slog.Info("supervisor: filter binary appeared while the data plane was fail-loud; reloading to spawn it",
		"event.name", "proxy.filter_stub_healing", "slug", cause.Slug, "binary", cause.ExpectedPath)
	if err := reload(s.ctx); err != nil {
		slog.Warn("supervisor: reload to clear the filter 501 failed; will retry next tick",
			"event.name", "proxy.filter_stub_heal_failed", "error", err)
	}
}

// computeFilterSig returns a stable signature of the vault's current filter-app
// set (sorted, comma-joined slugs). ok=false on read error so the caller skips
// the comparison rather than mistaking an error for a "set changed" → reload storm.
func computeFilterSig(vaultReader *vault.Reader) (string, bool) {
	slugs, err := vaultReader.GetFilterAppSlugs()
	if err != nil {
		return "", false
	}
	sort.Strings(slugs)
	// R9: fold each slug's filter_record_allow and filter_max_action into the signature so settings
	// toggle (not just enable/disable) also triggers a reload — installFilterHook
	// passes record_allow into the detector child's env, so a stale child would
	// otherwise keep the old value until a manual reload. (filter_stages VALUE
	// changes stay out of scope: the cluster daemon only flips the column
	// NULL<->["pre_forward"], which already changes the slug set.) A per-slug read
	// error defaults to false — harmless: at worst a record_allow flip is missed,
	// never a spurious reload.
	parts := make([]string, 0, len(slugs))
	for _, s := range slugs {
		ra, _ := vaultReader.GetFilterRecordAllow(s)
		maxAction, err := vaultReader.GetFilterMaxAction(s)
		if err != nil {
			maxAction = "invalid"
		}
		parts = append(parts, filterAppSignaturePart(s, ra, maxAction))
	}
	return strings.Join(parts, ","), true
}

func filterAppSignaturePart(slug string, recordAllow bool, maxAction string) string {
	return fmt.Sprintf("%s:%t:%s", slug, recordAllow, maxAction)
}

// filterSigWithPrivacyTier appends the org privacy tier to the filter signature.
//
// WHY THE TIER HAS TO BE IN THE SIGNATURE: installFilterHook bakes the tier into
// the detector child's ENVIRONMENT at spawn. A running child keeps whatever
// value it was born with, forever. So an admin lowering the tier from 3 to 1
// would change the server's policy, change what the server STORES (the master
// strips on ingest), and change nothing about what employees' machines SEND —
// raw text would keep traveling the network until something unrelated caused a
// reload. Folding the tier in here makes the poller's Reload actually re-spawn.
//
// It is separate from computeFilterSig because that function only reads the
// vault, while the tier lives on the supervisor. Same reason record_allow is
// folded in there and not here.
//
// 能红 check: drop the tier term and TestFilterSig_ChangesWithPrivacyTier fails.
func filterSigWithPrivacyTier(base string, tier int64) string {
	return base + "|tier:" + strconv.FormatInt(tier, 10)
}

// filterSigWithPasswordTier appends the org password-lane force to the filter
// signature, for the same reason as the privacy tier above: the value is baked
// into the detector child's ENV at spawn, so only a re-spawn can change what a
// running detector enforces. Dropping this term means an admin forcing
// `advanced` changes the policy server-side and nothing on members' machines
// until an unrelated reload. spec: R-credential-password-tier-4.S1
func filterSigWithPasswordTier(base string, advanced bool) string {
	return base + "|pwtier:" + strconv.FormatBool(advanced)
}

// syncManagedKeys checks the vault change_seq and, if it has advanced since
// the active generation was built, merges current active managed keys into the
// live registry.
func (s *Supervisor) syncManagedKeys() {
	gen := s.active.Load()

	// D-U7/P9 budget-mode freshness: feed the quota snapshot the last time the
	// TRAFFIC-INDEPENDENT heartbeat confirmed the server is reachable. Copying the
	// probe's timestamp on this 5s tick is enough — the probe advances it on its
	// own cadence. NOT the old reporter-upload time: that was request-driven, so it
	// went stale whenever the node was simply idle, which (under budget mode)
	// blocked the node and then deadlocked (the block stops the traffic that would
	// refresh it). nil heartbeat (availability mode / no collector URL) → leaves
	// lastReachableAt zero → budget mode inert (rollout-safe).
	if s.quotaHeartbeat != nil {
		s.quotaSnapshot.SetLastReachableAt(s.quotaHeartbeat.LastOKAt())
	}

	// P0 write-behind flush: persist the in-memory counter's local increment to
	// quota_local_usage every tick (not per request) so an OFFLINE restart resumes
	// from it. The in-memory counter stays the authority — this is a lossy backstop
	// (≤1 tick behind, safe side). Runs every tick regardless of vault-seq, before
	// the early-return below. Best-effort: a write failure only WARNs.
	s.flushLocalUsage()

	// SELF-HEAL while fail-loud (bugfix 2026-08-20). When the data plane is
	// refusing everything because a declared filter binary could not be
	// resolved, the cure is a FILE appearing — but every reload trigger below
	// keys on the vault's change_seq, and `aikey app install` laying the
	// binary down changes no vault row. Cause and cure sat on different axes,
	// so a machine that was fixed stayed 501 until someone restarted the proxy
	// (staging, 2026-08-20). Poll only while latched: one stat per tick in the
	// broken state, nothing at all in the healthy one.
	s.healFilterStubIfResolvable()

	vaultSeq, err := vault.ReadConfigU64LE(s.cfg.Vault.Path, VaultChangeSeqKey)
	if err != nil {
		return // vault not yet written or unavailable — no-op
	}
	loadedSeq, err := vault.ReadConfigU64LE(s.cfg.Vault.Path, ProxyLoadedSeqKey)
	if err != nil {
		loadedSeq = 0 // first run or missing key: treat as stale
	}
	if vaultSeq == loadedSeq {
		return // nothing changed
	}

	// Filter-app set change → trigger a FULL reload (not the lightweight
	// registry rebuild below). The compliance/DLP filter child lives on the
	// generation (g.filterHook), not the route registry, so a registry-only
	// rebuild cannot spawn/stop it. The cluster daemon toggles compliance by
	// writing the "cluster-compliance" app_record's filter_stages; without this
	// check that only took effect on a manual /admin/reload (2026-06-05 E2E gap).
	// Fault-isolated: a read error skips the check (never a reload storm).
	if baseSig, ok := computeFilterSig(gen.vault); ok {
		// Fold in the org privacy tier: it is baked into the detector child's env
		// at spawn, so only a re-spawn can change what a running detector sends.
		newSig := filterSigWithPasswordTier(filterSigWithPrivacyTier(baseSig, s.masterPrivacyTier.Load()), s.masterPasswordTierAdvanced.Load())
		if prev := s.lastFilterSig.Load(); prev == nil || *prev != newSig {
			// R5: record the attempted signature BEFORE the reload so a
			// persistently-failing Reload (e.g. transient build error) does NOT
			// re-fire every 5s tick (reload storm). On success buildGeneration
			// re-stores the same value + advances loaded_seq; on failure we keep
			// this stored value and fall through to the lightweight rebuild so
			// the credential sync still converges (loaded_seq advances) — the
			// filter just stays as-is until the vault filter set changes again.
			s.lastFilterSig.Store(&newSig)
			slog.Info("managed key sync: filter-app set changed; full reload",
				"event.name", "proxy.filter.set_changed")
			if rlErr := s.Reload(s.ctx); rlErr != nil {
				slog.Warn("managed key sync: filter-triggered reload failed; "+
					"continuing with lightweight sync (filter unchanged)", "error", rlErr)
				// fall through — do NOT return — so the cred path below still runs.
			} else {
				return // Reload rebuilt registry + filter hook + advanced loaded_seq.
			}
		}
	}

	totalRoutes := s.rebuildRouteRegistry(gen)
	// A Cluster material-only refresh advances vault.change_seq and replaces
	// group_runtime, but legitimately leaves assignment_override unchanged.
	// refreshClusterRoutingOverrides therefore has no assignment change to wake
	// the projection worker for. Re-stamp after every consumed vault snapshot so
	// the externally visible current_routed flag is rebuilt from the same fresh
	// material, assignment and process-wide cooldown/tombstone truth as the hot
	// path. The kick is non-blocking; SQLite work never joins this sync caller.
	s.requestCurrentRoutedRestamp()

	// Quota rules ride the same vault-seq advance (design §0.5/§5.2). This is
	// strictly after the managed-key path above and fully fault-isolated (gated
	// by the flag, swallows errors, keeps last-known-good) so a quota problem
	// can never disturb managed-key delivery — the proxy's main path.
	s.reloadQuotaSnapshot(gen)

	// Record that we've caught up to this seq.
	if werr := vault.WriteConfigU64LE(s.cfg.Vault.Path, ProxyLoadedSeqKey, vaultSeq); werr != nil {
		slog.Warn("managed key sync: failed to write loaded_vault_change_seq", "error", werr)
	} else {
		slog.Info("managed key sync: registry rebuilt",
			"total_routes", totalRoutes,
			"vault_seq", vaultSeq,
		)
	}
}

// rebuildRouteRegistry loads every token source from the vault and atomically
// replaces the route registry, returning how many routes were installed.
//
// 🔴 Why this is its own function (2026-08-26, revocation-window fix). It used to
// be the tail of syncManagedKeys, which is gated on the vault's change_seq — it
// early-returns when the LOCAL vault has not changed. That gate is correct for
// its own purpose and fatally wrong for a second caller: a seat suspended on the
// control plane changes nothing in this machine's vault, so a rebuild triggered
// through syncManagedKeys would have been skipped exactly when it mattered.
// The key_revocation rail therefore needs to reach the rebuild WITHOUT the seq
// gate, and the only alternatives were worse: a full Reload() re-spawns the
// filter child (the startup reload-storm bugfix, 20260725) and a second
// hand-rolled route builder would split the source of truth for what a route is.
//
// See workflow/CI/bugfix/20260826-proxy-revocation-window-unbounded.md.
func (s *Supervisor) rebuildRouteRegistry(gen *generation) int {
	// Full rebuild: load all token sources and atomically replace the registry.
	// Why ReplaceAll instead of Merge: deleted/revoked tokens must be removed
	// immediately. Merge is additive and cannot remove stale entries.
	allRoutes := make(map[string]*vkeys.ResolvedRoute)

	// Source 1 (static YAML virtual_keys[]) was removed in Stage C-2.c.
	// All routes now come from vault — see workflow/CD/templates/removed-registry.yaml.

	// 2. Team managed keys
	managedKeys, err := gen.vault.GetActiveManagedKeys()
	if err != nil {
		slog.Warn("managed key sync: GetActiveManagedKeys failed", "error", err)
	} else {
		// Cluster daemon writes the allocation assignment into the same vault
		// snapshot as group material. Refresh the supervisor-scoped hot-path cache
		// on this existing change-seq cycle; rebuilding registry routes alone does
		// not update RoutingOverrideCache.
		s.refreshClusterRoutingOverrides(managedKeys)
	}
	for token, route := range buildManagedRoutes(managedKeys, s.revokedVKs()) {
		allRoutes[token] = route
	}

	// 3. Personal key route tokens. Strict-form filter is centralized in
	// buildPersonalRoutesFiltered (route_builders.go) — same helper used
	// by buildGeneration's startup path so the two never drift. Legacy
	// `aikey_vk_<64-hex>` and any non-strict shape get WARN-skipped; per
	// "no double-prefix compatibility window" principle they MUST NOT be
	// silently re-registered. See review #5 [中], 2026-04-29.
	if personalTokens, ptErr := gen.vault.GetAllPersonalRouteTokens(); ptErr == nil {
		for tok, route := range buildPersonalRoutesFiltered(personalTokens) {
			allRoutes[tok] = route
		}
	} else if !errors.Is(ptErr, vault.ErrMissingRouteTokenColumn) {
		slog.Warn("managed key sync: GetAllPersonalRouteTokens failed", "error", ptErr)
	}

	// 4. OAuth account route tokens. Same shared filter as personal.
	if oauthTokens, otErr := gen.vault.GetAllOAuthRouteTokens(); otErr == nil {
		for tok, route := range buildOAuthRoutesFiltered(oauthTokens) {
			allRoutes[tok] = route
		}
	} else if !errors.Is(otErr, vault.ErrMissingRouteTokenColumn) {
		slog.Warn("managed key sync: GetAllOAuthRouteTokens failed", "error", otErr)
	}

	// 5. App pipeline bearers (Phase 4 `aikey_app_*` tokens). Without this
	// block, `aikey app rotate / revoke / pause / resume / register / route`
	// would silently require `aikey proxy restart` because the only other
	// place GetAllAppRouteTokens is called is buildGeneration (startup +
	// /admin/reload). The `proxy_vault_state()` indicator would still report
	// Current after the seq write below, which makes the silent staleness
	// strictly worse than printing a restart hint — see
	// memory: no-proxy-restart-for-vault-mutations.
	//
	// ReplaceAll handles revoke/pause/resume atomically (a deleted/paused
	// token simply doesn't appear in allRoutes → vanishes on swap).
	if appTokens, atErr := gen.vault.GetAllAppRouteTokens(); atErr == nil {
		for tok, route := range buildAppRoutesFiltered(appTokens) {
			allRoutes[tok] = route
		}
	} else {
		slog.Warn("managed key sync: GetAllAppRouteTokens failed", "error", atErr)
	}

	// Atomic replace — deleted/revoked tokens disappear immediately.
	gen.registry.ReplaceAll(allRoutes)
	return len(allRoutes)
}

// quotaEnabledFromEnv reads the PROXY_QUOTA_ENABLED switch. Default ON
// (2026-06-11 flip, user-approved): the old default-OFF was a Phase-2
// Stage-2 guard ("rail built, enforcement not landed yet") that outlived
// its purpose once Stage 3 shipped — and it caused a real incident: the
// cluster worker role forgot to set the env, so enterprise hard_block
// quotas were SILENTLY unenforced on fleet nodes (bug
// 20260611-cluster-worker-quota-not-enabled). Whether quota acts should be
// decided by ONE truth source — "did an admin configure rules" — not
// additionally by "did ops remember an env var".
//
// Default-ON is safe by the enforcer's invariant 6 (quota_enforce.go): a
// snapshot with no rules is a pure in-memory no-op — Personal installs and
// org-less proxies see zero behavior change; only a confirmed over-limit
// blocks. PROXY_QUOTA_ENFORCE_MODE=budget (fail-closed) stays strictly
// opt-in and is NOT affected by this flip.
//
// The env is kept as an explicit OPT-OUT kill switch: "0"/"false"/"no"/
// "off" (case-insensitive) disables enforcement for emergency rollback.
func quotaEnabledFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PROXY_QUOTA_ENABLED"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// quotaBudgetModeFromEnv reads enforce_mode (D-U7/P9, deployment-level).
// PROXY_QUOTA_ENFORCE_MODE=budget enables strict fail-closed-on-staleness; anything
// else (default) = availability (offline-first, never fails closed).
// PROXY_QUOTA_MAX_STALENESS_SECONDS sets the threshold (default 300s). Per-subject
// override deferred (D-U7).
func quotaBudgetModeFromEnv() (budget bool, maxStaleness time.Duration) {
	if strings.ToLower(strings.TrimSpace(os.Getenv("PROXY_QUOTA_ENFORCE_MODE"))) != "budget" {
		return false, 0
	}
	secs := 300
	if v := strings.TrimSpace(os.Getenv("PROXY_QUOTA_MAX_STALENESS_SECONDS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			secs = n
		}
	}
	return true, time.Duration(secs) * time.Second
}

// reloadQuotaSnapshot loads the quota rules cached in the vault and atomically
// swaps them into the in-memory snapshot. Fully fault-isolated: gated by the
// feature flag, and on any error it logs a WARN and KEEPS the last-known-good
// snapshot (design §8) — it never returns an error and never touches the
// managed-key path. Called at startup / reload (buildGeneration) and on each
// vault-seq advance (syncManagedKeys).
// flushLocalUsage persists the counter's current local increments to the vault's
// quota_local_usage table (P0 write-behind). Best-effort + no-op when quota is off
// or there's nothing to persist. Writes via its own connection (WriteLocalUsage)
// so it never contends on the shared read path. A failure only WARNs — the
// in-memory counter remains authoritative; the persisted copy just lags a tick.
func (s *Supervisor) flushLocalUsage() {
	if !s.quotaEnabled || s.quotaCounter == nil {
		return
	}
	rows := s.quotaCounter.IncrementRows()
	if len(rows) == 0 {
		return
	}
	if err := quota.WriteLocalUsage(s.cfg.Vault.Path, rows); err != nil {
		slog.Warn("quota.local_usage.flush_failed", "error", err.Error())
	}
}

func (s *Supervisor) reloadQuotaSnapshot(gen *generation) {
	if !s.quotaEnabled || gen == nil || gen.vault == nil {
		return
	}
	subjects, err := quota.LoadSubjects(gen.vault.DB())
	if err != nil {
		slog.Warn("quota.snapshot.load_failed", "error", err.Error())
		return
	}
	s.quotaSnapshot.ReplaceAll(subjects)
	// Stage 4 回填: seed each subject's counter from the control-reported
	// current-period baseline so a restart/another machine doesn't resume from
	// zero. Idempotent on unchanged baselines (won't wipe local increments).
	quota.SeedBaselines(s.quotaCounter, subjects, time.Now())
	// P0 (write-behind restore): restore the persisted local increment ONCE at
	// startup, BEFORE serving, so an OFFLINE restart resumes from the usage accrued
	// since the last server baseline rather than zero. Must be once-only — re-seeding
	// on a later reload would clobber in-flight increments. A missing table (pre-P0
	// vault) loads as empty → start from zero, harmless. On a read error, leave the
	// flag false to retry next reload.
	if !s.quotaIncrementSeeded {
		if rows, lerr := quota.LoadLocalUsage(gen.vault.DB()); lerr != nil {
			slog.Warn("quota.local_usage.load_failed", "error", lerr.Error())
		} else {
			quota.SeedLocalIncrements(s.quotaCounter, rows)
			s.quotaIncrementSeeded = true
			slog.Info("quota.local_usage.seeded", "rows", len(rows))
		}
	}
	slog.Info("quota.snapshot.loaded", "subjects", len(subjects))
	// D-U8/P6: load the deployment-global edge price summary (for P7 local usd
	// pricing). Best-effort — a read/parse failure logs WARN and KEEPS the
	// last-good summary; an absent summary (nil) also keeps last-good. Never
	// disturbs the snapshot reload or the managed-key path.
	if ps, err := quota.LoadPriceSummary(gen.vault.DB()); err != nil {
		slog.Warn("quota.price_summary.load_failed", "error", err.Error())
	} else if ps != nil {
		s.quotaSnapshot.SetPriceSummary(ps)
		slog.Info("quota.price_summary.loaded", "version", ps.Version, "models", len(ps.Models))
	}
}

// QuotaSnapshot exposes the live rule snapshot (Stage 3 enforcement + tests).
func (s *Supervisor) QuotaSnapshot() *quota.Snapshot { return s.quotaSnapshot }

// QuotaCounter exposes the in-memory counter (Stage 3 enforcement + tests).
func (s *Supervisor) QuotaCounter() *quota.Counter { return s.quotaCounter }

// Handler returns an http.Handler that always delegates to the active generation.
// This is the function passed to the http.Server — it never changes across reloads.
//
// Hot path: no nil-check on s.active. The first generation is Load()-ed in the
// constructor before Serve() ever accepts a connection, and Reload only ever
// Stores a non-nil generation, so a nil here is an impossible lifecycle bug, not
// a runtime condition — guarding it would silently swallow that bug instead of
// crashing visibly. The nil-checked accessors elsewhere (EffectivePacks etc.)
// differ because admin/test paths can call them before the first generation is
// ready, where nil is a legitimate "not yet available" state.
// 🔴 Task 1b.6 — this is the ONE place the fallback thresholds are snapshotted.
// Every data-plane request enters here (the server mounts this handler on the
// catch-all route), so taking the snapshot once at this point and passing it down
// the context is what makes 「整条链共用一份快照」 structural rather than a habit
// each future hop has to remember. A per-hop re-read would let a 10-second poll
// landing mid-request give hops 1–2 one timeout and hop 3 another — identical
// inputs, different behavior, and no log line explaining it. The source fence in
// internal/proxy asserts SnapshotForRequest has exactly this one caller.
func (s *Supervisor) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(proxy.WithFallbackPolicy(r.Context(), s.fallbackPolicy.SnapshotForRequest()))
		s.active.Load().ServeHTTP(w, r)
	})
}

// EventStore returns the current generation's event store (for admin metrics).
func (s *Supervisor) EventStore() *events.Store {
	return s.active.Load().eventStore
}

// Registry returns the current generation's virtual key registry.
func (s *Supervisor) Registry() *vkeys.Registry {
	return s.active.Load().registry
}

// TotalRequests returns the proxy's cumulative request counter.
func (s *Supervisor) TotalRequests() int64 {
	return s.active.Load().proxy.TotalRequests()
}

// TotalErrors returns the proxy's cumulative error counter.
func (s *Supervisor) TotalErrors() int64 {
	return s.active.Load().proxy.TotalErrors()
}

// EffectivePacks queries the ACTIVE generation's compliance filter child for the
// packs currently effective in it (built-in baseline + pulled). Returns the raw
// JSON report. Always reads s.active (never a cached hook), so after a Reload
// re-spawns the child it hits the new live process — same source as Detect.
// Returns apphook.ErrPacksUnavailable when no filter child is active; admin maps
// that to "packs unavailable", never an error that touches the data plane.
func (s *Supervisor) EffectivePacks(ctx context.Context) ([]byte, error) {
	g := s.active.Load()
	if g == nil || g.filterHook == nil {
		return nil, apphook.ErrPacksUnavailable
	}
	return g.filterHook.ListPacks(ctx)
}

// FilterPerformanceSnapshot returns the active generation's content-free
// compliance latency window. Reload starts a fresh window by construction.
func (s *Supervisor) FilterPerformanceSnapshot() proxy.FilterPerformanceSnapshot {
	g := s.active.Load()
	if g == nil || g.proxy == nil {
		return proxy.FilterPerformanceSnapshot{}
	}
	return g.proxy.FilterPerformanceSnapshot()
}

// AppHealthSnapshot returns the active proxy generation's in-memory "most
// recent app-pipeline call per slug" snapshot. Drives the Web "Connected
// Apps" list Health column via the /admin/apps/health endpoint.
//
// Each Reload swaps in a fresh *Proxy with an empty cache — that matches
// the "config changed; previously-observed health may be stale" intuition
// (the new generation will repopulate as traffic flows). Persisting
// across reloads would require either a sidecar store or copying the map
// — neither warranted for "list-page health badge".
func (s *Supervisor) AppHealthSnapshot() []apppipe.AppHealth {
	return s.active.Load().proxy.AppHealthSnapshot()
}

// PoolCooldownSnapshot returns oauth-group accounts currently cooling down
// (account_id → seconds remaining) from the active generation's proxy, for the
// admin /status pool-routing health surface (N9).
func (s *Supervisor) PoolCooldownSnapshot() map[string]int {
	return s.active.Load().proxy.PoolCooldownSnapshot()
}

// PoolRouteStateSnapshot exposes display-only reason/retry metadata for the
// same whole-account cooldown set. Routing continues to read the cooldown store
// directly; heartbeat and admin status are observers only.
func (s *Supervisor) PoolRouteStateSnapshot() map[string]proxy.PoolAccountRouteState {
	return s.active.Load().proxy.CooldownRouteStateSnapshot()
}

// PoolAuthFailureSnapshot exposes exact group+seat+account hard-revocation
// states for health surfaces without widening the routing scope.
func (s *Supervisor) PoolAuthFailureSnapshot() []proxy.PoolAuthFailureState {
	return s.active.Load().proxy.AuthFailureRouteSnapshot()
}

// ProviderPathHealthSnapshot returns the shared OAuth-group outbound-path
// breaker state for /status. Unlike account cooldowns it survives Proxy reloads.
func (s *Supervisor) ProviderPathHealthSnapshot() []proxy.ProviderPathHealth {
	return s.pathHealth.Snapshot()
}

// SignalReportingHealthSnapshot returns the active generation's Proxy→Master
// allocation-signal health. The pointer is nil when the feature is not wired.
func (s *Supervisor) SignalReportingHealthSnapshot() *proxy.SignalReportingHealth {
	gen := s.active.Load()
	if gen == nil || gen.proxy == nil {
		return nil
	}
	return gen.proxy.SignalReportingHealthSnapshot()
}

// ReporterMetrics returns usage reporter counters from the active generation.
// Returns nil if reporter is not configured (no collector_url).
func (s *Supervisor) ReporterMetrics() *events.ReporterMetrics {
	gen := s.active.Load()
	if gen.reporter == nil {
		return nil
	}
	m := gen.reporter.Metrics()
	return &m
}

// CollectorMetrics returns the active generation's collector counters (queue-full
// drops). Returns nil if no collector is active. Mirrors ReporterMetrics so
// GET /admin/audit/status exposes both billing-loss paths.
//
// 🔴 The route is /admin/audit/status, NOT /admin/metrics (comment fixed
// 2026-08-21). No /admin/metrics route has ever existed — three comments named
// it, so an operator following them hits the data-plane catch-all and gets a
// 401 TOKEN_MISSING from the LLM gateway, which reads like an auth problem
// rather than a wrong path. It cost a diagnosis session exactly that way.
// Loopback callers need no token (server/adminauth.go loopbackOK).
func (s *Supervisor) CollectorMetrics() *events.CollectorMetrics {
	gen := s.active.Load()
	if gen == nil || gen.collector == nil {
		return nil
	}
	m := gen.collector.Metrics()
	return &m
}

// ReplayDeadLetter triggers a dead-letter replay pass on the active
// generation's reporter. Returns ErrNoReporter when the reporter isn't
// configured (no collector_url) so callers (admin handler) can map to
// 503 instead of a misleading "0 entries scanned" success.
//
// Added 2026-05-11 for the B-phase follow-up — see
// internal/events/dead_letter.go::Reporter.ReplayDeadLetter docstring
// for full semantics.
func (s *Supervisor) ReplayDeadLetter(ctx context.Context) (events.ReplayDeadLetterResult, error) {
	gen := s.active.Load()
	if gen.reporter == nil {
		return events.ReplayDeadLetterResult{}, fmt.Errorf("reporter not configured")
	}
	return gen.reporter.ReplayDeadLetter(ctx)
}

// AuditStatus returns the active generation's local delivery state for `aikey
// audit status` (D2.5). Returns nil if the reporter isn't configured.
func (s *Supervisor) AuditStatus() *events.AuditStatus {
	gen := s.active.Load()
	if gen == nil || gen.reporter == nil {
		return nil
	}
	st := gen.reporter.AuditStatus()
	return &st
}

// ReconcileGaps triggers a client-confirmed reconciliation pass (D3) on the
// active generation's reporter. Errors when the reporter isn't configured.
func (s *Supervisor) ReconcileGaps(ctx context.Context) (events.ReconcileResult, error) {
	gen := s.active.Load()
	if gen == nil || gen.reporter == nil {
		return events.ReconcileResult{}, fmt.Errorf("reporter not configured")
	}
	return gen.reporter.ReconcileGaps(ctx)
}

// CanaryResult returns the latest canary probe result from the active generation.
// Returns nil if canary probe is not configured.
func (s *Supervisor) CanaryResult() *events.CanaryResult {
	gen := s.active.Load()
	if gen.canary == nil {
		return nil
	}
	r := gen.canary.LastResult()
	if r.EventID == "" {
		return nil // no probe has run yet
	}
	return &r
}

// InflightRequests returns the number of in-flight requests in the active generation.
func (s *Supervisor) InflightRequests() int64 {
	return s.active.Load().inflight.Load()
}

// HealthSnapshot returns a point-in-time health summary for logging.
func (s *Supervisor) HealthSnapshot() observability.HealthSnapshot {
	gen := s.active.Load()
	snap := observability.HealthSnapshot{
		Status:           "ok",
		GenerationID:     gen.id,
		InflightRequests: gen.inflight.Load(),
		TotalRequests:    gen.proxy.TotalRequests(),
		TotalErrors:      gen.proxy.TotalErrors(),
		UptimeSeconds:    time.Since(s.startedAt).Seconds(),
	}
	if vaultSeq, err := vault.ReadConfigU64LE(s.cfg.Vault.Path, VaultChangeSeqKey); err == nil {
		snap.VaultChangeSeq = vaultSeq
	}
	if loadedSeq, err := vault.ReadConfigU64LE(s.cfg.Vault.Path, ProxyLoadedSeqKey); err == nil {
		snap.ProxyLoadedSeq = loadedSeq
	}
	if snap.TotalErrors > 0 && snap.TotalRequests > 0 {
		errRate := float64(snap.TotalErrors) / float64(snap.TotalRequests)
		if errRate > 0.1 { // >10% error rate → degraded
			snap.Status = "degraded"
		}
	}
	return snap
}

// ResolveUpstreamForSourceRef answers "which upstream would the DATA PLANE dial
// for this credential?" — the question /admin/probe/ping must ask before it can
// honestly claim to have tested that credential.
//
// 🔴 It resolves through proxy.ResolvePersonalUpstreamBase, the SAME function the
// forwarding path calls. That sharing is the point, not an optimisation: the
// probe used to guess the upstream from the provider code, so an entry with its
// own base_url (a self-hosted gateway, an OAuth ingress) was tested against a
// public host it never talks to. The verdict then tracked the wrong host in both
// directions — red while the real gateway was healthy, and GREEN while it was
// down. requirements/2026-07-18 §上游地址单一解析 「展示=执行」.
//
// Scope today is PERSONAL vault aliases — the shape `aikey test <alias>` sends
// for a personal entry. Team / OAuth references resolve elsewhere (delivered
// bindings, broker) and are NOT handled here yet; they return an error, which
// the caller surfaces rather than papers over, so the gap stays visible instead
// of silently degrading to the old guess.
func (s *Supervisor) ResolveUpstreamForSourceRef(sourceRef, protocolHint string) (string, error) {
	if strings.TrimSpace(sourceRef) == "" {
		return "", fmt.Errorf("empty source_ref")
	}
	gen := s.active.Load()
	if gen == nil || gen.vault == nil {
		return "", fmt.Errorf("vault not available")
	}
	// The plaintext key is deliberately discarded: a reachability probe needs an
	// ADDRESS, never a credential. This reader is the only one that exposes the
	// entry's base_url, so the decryption is unavoidable here — keeping the value
	// unnamed makes it impossible to leak into a log line or a response by a
	// later edit.
	_, entryProviderCode, entryBaseURL, err := gen.vault.GetPersonalKeyByAlias(sourceRef)
	if err != nil {
		return "", fmt.Errorf("resolve personal alias %q: %w", sourceRef, err)
	}
	base := proxy.ResolvePersonalUpstreamBase(entryBaseURL, entryProviderCode, protocolHint)
	if base == "" {
		return "", fmt.Errorf("no upstream address on file for %q", sourceRef)
	}
	return base, nil
}

// GetKeyCheckTargets resolves the active key's decrypted credentials for each
// provider it supports. Used by GET /health/keys to probe key validity.
// Returns nil (no error) when no key is active.
func (s *Supervisor) GetKeyCheckTargets() ([]admin.KeyCheckTarget, error) {
	gen := s.active.Load()
	if gen == nil {
		return nil, nil
	}
	cfg, err := gen.vault.GetActiveKeyConfig()
	if err != nil {
		// A vault READ FAILURE is not "there are no keys". Returning (nil, nil)
		// here made /health/keys answer "no active key configured" while the
		// vault was actually unreadable — a broken pipeline that looks healthy,
		// which health-signal-surface exists to forbid. Worse, an operator
		// reading that could conclude the proxy has no keys and re-import /
		// re-provision a vault that is perfectly fine.
		//
		// This outer guard also silently defeated the inner loop below, which was
		// deliberately fixed to WARN on a per-provider resolve failure: none of
		// that care could ever run once the config read itself was swallowed.
		//
		// HealthKeys already distinguishes this case ("key resolution failed: …",
		// still HTTP 200 per contract) from len==0 ("no active key configured") —
		// it just never received the error to distinguish. (2026-07-13)
		slog.Error("active key config read failed for health probe",
			"event.name", "usage.health.key_config_read_failed",
			"error.code", "KEY_CONFIG_READ_FAILED",
			"error", err.Error())
		return nil, fmt.Errorf("read active key config: %w", err)
	}
	if cfg == nil {
		return nil, nil // genuinely no active key — the documented empty case
	}

	var targets []admin.KeyCheckTarget
	switch cfg.KeyType {
	case "team":
		for _, clientRoute := range cfg.Providers {
			// active_key_providers is a legacy name: current CLI versions store
			// client routes here. Resolve the exact active binding first so a
			// Mock+Anthropic key is probed as provider=mock/protocol=anthropic,
			// never as a fictitious provider=anthropic key or a Mock protocol.
			binding, bindErr := gen.vault.GetProviderBinding(clientRoute)
			if bindErr != nil {
				slog.Warn("team key binding resolve failed for health probe",
					"event.name", "usage.health.team_binding_resolve_failed",
					"error.code", "KEY_BINDING_RESOLVE_FAILED",
					"client_route", clientRoute,
					"error", bindErr)
				continue
			}

			var mk *vault.ManagedKey
			var err error
			if binding != nil {
				if binding.KeySourceType != "team" && binding.KeySourceType != "managed_virtual_key" {
					slog.Warn("team active config points to a non-team binding",
						"event.name", "usage.health.team_binding_type_mismatch",
						"error.code", "KEY_BINDING_TYPE_MISMATCH",
						"client_route", clientRoute,
						"key_source_type", binding.KeySourceType)
					continue
				}
				mk, err = gen.vault.GetTeamKeyByID(
					binding.KeySourceRef, binding.ProviderCode, binding.ProtocolType)
			} else {
				// Pre-binding-table compatibility only. There is no exact Provider
				// or Protocol available in this legacy state.
				mk, err = gen.vault.GetActiveTeamKeyByProvider(clientRoute, "")
			}
			if err != nil || mk == nil {
				// WHY: a team key that fails to resolve/decrypt used to be silently
				// skipped here, so /health/keys just showed fewer keys and ops had no
				// externally-readable signal that a credential is broken. Surface it as
				// a structured WARN (health-signal-surface + logging-conventions) before
				// continuing — control flow is unchanged so one bad provider does not
				// block probing the others.
				if err != nil {
					slog.Warn("team key decrypt/resolve failed for health probe",
						"event.name", "usage.health.team_key_decrypt_failed",
						"error.code", "KEY_DECRYPT_FAILED",
						"client_route", clientRoute,
						"error", err,
					)
				}
				continue
			}
			baseURL := mk.BaseURL
			if baseURL == "" {
				if u, ok := mk.ProviderBaseURLs[mk.ProviderCode]; ok && u != "" {
					baseURL = u
				}
			}
			targets = append(targets, admin.KeyCheckTarget{
				Provider: mk.ProviderCode,
				Protocol: mk.ProtocolType,
				BaseURL:  baseURL,
				APIKey:   mk.PlaintextKey,
				KeyRef:   cfg.KeyRef,
			})
		}
	case "personal":
		plaintext, storedCode, baseURL, err := gen.vault.GetPersonalKeyByAlias(cfg.KeyRef)
		if err != nil {
			return nil, fmt.Errorf("resolve personal key: %w", err)
		}
		// Build the provider list: prefer cfg.Providers (written by `aikey use`); fall back to
		// the stored provider_code; final fallback is "openai" for generic gateways.
		providerList := cfg.Providers
		if len(providerList) == 0 {
			if storedCode != "" {
				providerList = []string{storedCode}
			} else {
				providerList = []string{"openai"}
			}
		}
		for _, pcode := range providerList {
			// Resolve the endpoint row as a pair. A custom URL is authoritative;
			// otherwise the Provider must have one unambiguous protocol in the
			// routing table. Do not restore the former provider→protocol switch.
			resolvedProvider := pcode
			protocol := ""
			burl := baseURL
			if burl != "" {
				if route, ok := provider.Routes().LookupByBaseURL(burl); ok {
					resolvedProvider = route.Provider
					protocol = route.Protocol
				} else {
					protocol, _ = provider.ProtocolFamily(pcode, "")
				}
			} else if uniqueProtocol, ok := provider.ProtocolFamily(pcode, ""); ok {
				protocol = uniqueProtocol
				burl = providerBaseURLForProtocol(pcode, protocol)
			}
			if protocol == "" || burl == "" {
				slog.Warn("personal key health target has no exact provider/protocol route",
					"event.name", "usage.health.personal_route_unresolved",
					"provider", pcode,
					"key_ref", cfg.KeyRef)
				continue
			}
			targets = append(targets, admin.KeyCheckTarget{
				Provider: resolvedProvider,
				Protocol: protocol,
				BaseURL:  burl,
				APIKey:   plaintext,
				KeyRef:   cfg.KeyRef,
			})
		}
	}
	return targets, nil
}

// Reload builds a new generation, swaps it as active if the readiness gate
// passes, drains the old generation, and records the loaded vault change_seq.
// It serializes concurrent calls: a second Reload waits for the first to finish.
func (s *Supervisor) Reload(ctx context.Context) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	reloadID := observability.NewID()
	old := s.active.Load()

	slog.Info("reload: building new generation",
		"event.name", observability.EventProxyReloadStarted,
		"reload_id", reloadID,
		"old_generation_id", old.id,
	)

	// Re-read the config file so that changes to collector_url,
	// collector_token, virtual_keys, etc. are picked up on reload
	// instead of requiring a full stop+start cycle.  (Issue #19)
	if s.configPath != "" {
		newCfg, err := config.Load(s.configPath)
		if err != nil {
			slog.Error("reload: failed to re-read config, using previous config",
				"reload_id", reloadID,
				"config_path", s.configPath,
				"error.message", err.Error(),
			)
			// Continue with existing s.cfg — a config parse error should not
			// block a vault-only reload.
		} else {
			s.cfg = newCfg
			slog.Info("reload: config re-read",
				"reload_id", reloadID,
				"collector_url", s.cfg.Events.CollectorURL,
			)
		}
	}

	newGen, err := s.buildGeneration()
	if err != nil {
		slog.Error("reload: build generation failed",
			"event.name", observability.EventProxyReloadFailed,
			"reload_id", reloadID,
			"error.message", err.Error(),
		)
		return fmt.Errorf("reload: build generation failed: %w", err)
	}

	// Apply the latest supervisor-owned runtime state and swap under the same short
	// fence used by hot updates. The generation build above remains off-lock.
	s.activateGeneration(newGen)
	// The process-wide cooldown truth may have changed while the replacement was
	// building; re-stamp the display projection after it becomes active.
	s.requestCurrentRoutedRestamp()
	slog.Info("reload: new generation active",
		"event.name", observability.EventProxyReloadCompleted,
		"reload_id", reloadID,
		"generation_id", newGen.id,
	)

	// Record which vault snapshot the new generation loaded.
	if vaultSeq, err := vault.ReadConfigU64LE(s.cfg.Vault.Path, VaultChangeSeqKey); err == nil {
		if werr := vault.WriteConfigU64LE(s.cfg.Vault.Path, ProxyLoadedSeqKey, vaultSeq); werr != nil {
			slog.Warn("reload: failed to write loaded_vault_change_seq",
				"reload_id", reloadID,
				"error", werr,
			)
		} else {
			slog.Info("reload: wrote loaded_vault_change_seq",
				"reload_id", reloadID,
				"seq", vaultSeq,
			)
		}
	}

	// Drain the old generation asynchronously so the reload call returns promptly.
	// Isolated: if the drain panics the old generation leaks (FDs, memory),
	// which is bad but not immediately fatal — the new generation is already
	// serving. Keep the proxy up and emit a crash dump for post-mortem.
	observability.GoSafe("supervisor.reload.drain_old", observability.Isolated, func() {
		old.drain(drainTimeoutStreaming, reloadID)
		old.close()
		slog.Info("reload: old generation closed",
			"reload_id", reloadID,
			"generation_id", old.id,
		)
	})

	// SyncRail convergence (§5.2, 2026-07-03): a reload usually follows a config /
	// vault change (`aikey account set-url`, login, settings save). Drop the
	// cached team credential so the next cycle rebuilds against the CURRENT
	// control URL, and nudge every rail to run that cycle NOW — the settings
	// change converges in seconds instead of one poll interval. Both calls are
	// non-blocking (kick channels are buffered); the 60s per-cycle URL re-check
	// remains the bottom-line self-heal when no reload ever fires.
	if s.teamCred != nil {
		s.teamCred.invalidate()
	}
	if s.railset != nil {
		s.railset.kickAll()
	}

	return nil
}

// Shutdown drains the active generation and closes all resources.
func (s *Supervisor) Shutdown(timeout time.Duration) {
	// Cancel the proxy lifecycle context to abort any detached upstream calls.
	s.cancel()
	gen := s.active.Load()
	slog.Info("supervisor shutting down", "generation_id", gen.id)
	gen.drain(timeout, "shutdown")
	// The teardown below is a WATCHDOGGED stage (bugfix
	// 2026-08-19-proxy-shutdown-unbounded-close): generation.close() strings
	// together reporter/WAL/SQLite closes, and an unbounded wait anywhere in
	// that chain once held the drained process hostage until systemd's 90s
	// SIGKILL — killing rolling upgrades and the self-heal restart path (which
	// reuses this exact function). Every subsystem is expected to close within
	// its own budget (reporters: shutdownFlushBudget); the watchdog is the
	// structural fence for the ones that can't promise it (SQLite on a wedged
	// disk, future additions). On overrun: dump all goroutine stacks to stderr
	// (journald/launchd log = persisted forensic evidence, per the "超时退出必须
	// 自动保存诊断证据" acceptance bar) and return — abandoning teardown is safe
	// here because the process is about to exit and the WAL/SQLite layers are
	// crash-safe by design.
	closed := make(chan struct{})
	go func() {
		gen.close()
		if s.oauthPoolRuntime != nil {
			_ = s.oauthPoolRuntime.Shutdown()
		}
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(closeWatchdogTimeout):
		slog.Error("supervisor shutdown: teardown watchdog fired — dumping goroutines and abandoning close",
			"event.name", observability.EventProxyShutdownWatchdogTimeout,
			"generation_id", gen.id,
			"watchdog_seconds", int(closeWatchdogTimeout/time.Second))
		dumpGoroutineStacks()
	}
}

// closeWatchdogTimeout bounds the whole post-drain teardown. It must stay well
// under every OS stop timeout that supervises this process (systemd
// TimeoutStopSec=90 on cluster nodes; launchd ExitTimeOut default 20s is the
// tightest) so a graceful stop always beats the OS kill.
const closeWatchdogTimeout = 15 * time.Second

// dumpGoroutineStacks writes every goroutine's stack to stderr. Debug level 2
// (full stacks with goroutine states) is what actually answers "WHICH close is
// stuck on WHAT" — the exact evidence that was missing when workers hung until
// SIGKILL with nothing in the journal but the last drained log line.
func dumpGoroutineStacks() {
	if p := pprof.Lookup("goroutine"); p != nil {
		_ = p.WriteTo(os.Stderr, 2)
	}
}

// buildGeneration creates a fully-initialized generation ready to handle requests.
func (s *Supervisor) buildGeneration() (*generation, error) {
	id := int(s.genID.Add(1))

	// Open vault.
	vaultReader, err := vault.Open(s.cfg.Vault.Path, s.password)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}
	// Re-arm the control-plane revocation filter on the FRESH reader. A Reload
	// builds a new *vault.Reader, which starts with no filter — without this a
	// reload would silently un-revoke every suspended key until the next
	// key_revocation cycle (up to 60s of serving traffic that was already cut
	// off). Cheap and idempotent; empty set on a proxy that has never polled.
	vaultReader.SetRevokedVirtualKeys(s.revokedVKs())

	// Build virtual key registry. Stage C-2.c removed the static-yaml
	// loading path (was: iterate s.cfg.VirtualKeys → registry.Load).
	// All routes now flow in via Merge / ReplaceAll from vault-backed
	// sources (managed_virtual_keys_cache, personal_route_token,
	// oauth_route_token). See workflow/CD/templates/removed-registry.yaml.
	registry := vkeys.NewRegistry()

	// Load team-managed virtual keys from managed_virtual_keys_cache.
	// These are keys accepted via `aikey key accept` and activated via `aikey key use`.
	// Post-2026-04-29 prefix rename: bearer token = NormalizeTeamToken(vk_id),
	// which produces `aikey_team_<vk_id>` (with defensive strip of any
	// historical-prefix dirty data in the cache).
	if managedKeys, mkErr := vaultReader.GetActiveManagedKeys(); mkErr != nil {
		slog.Warn("could not load managed virtual keys", "error", mkErr)
	} else if len(managedKeys) > 0 {
		registry.Merge(buildManagedRoutes(managedKeys, s.revokedVKs()))
	}

	// Load personal-key + OAuth bearers (v1.0.4+) into the registry.
	//
	// Random `aikey_personal_<64-hex>` bearers generated by CLI for personal
	// API keys + OAuth accounts (post-2026-04-29 prefix rename — was previously
	// `aikey_vk_<64-hex>`), allowing third-party clients (Cursor, OpenCode)
	// to route through the proxy.
	//
	// Wired through `loadVaultRoutesIntoRegistry` (route_builders.go) so the
	// startup load path and the reload path (syncManagedKeys, also calling
	// the same `build*RoutesFiltered` helpers underneath) cannot drift on
	// what counts as "registry-eligible". Pre-migration vaults carrying
	// legacy `aikey_vk_<64-hex>` or other non-strict shapes get
	// WARN-skipped at this entrypoint instead of slipping into registry
	// state and surfacing as opaque 401s on first request. Per the
	// "no double-prefix compatibility window" principle. See review #5 [中],
	// 2026-04-29 (second pass — wiring evidence is now testable in
	// `TestLoadVaultRoutesIntoRegistry_StartupPathFiltersLegacy`).
	// Cluster policy (V3c P4.2): a cluster node serves ONLY team/managed virtual
	// keys. Skip loading personal / OAuth / app bearers so the node never routes
	// a developer's personal credential. (In practice a node's daemon-managed
	// vault.db has no personal/oauth/app rows anyway — this is defense-in-depth so
	// a misconfigured node can't leak them.) Team/managed routes are loaded
	// separately via the managed-key path, so the registry still gets them.
	if !s.cfg.Cluster.Enabled {
		loadVaultRoutesIntoRegistry(registry, vaultReader)
	}

	// Provider registry.
	providers := provider.NewRegistry()

	// Event store and collector (each generation gets its own collector goroutine,
	// sharing the same underlying SQLite store path so events are not lost).
	eventStore, err := events.OpenStore(s.cfg.Events.DBPath)
	if err != nil {
		_ = vaultReader.Close()
		return nil, fmt.Errorf("open events store: %w", err)
	}
	collector := events.NewCollector(eventStore, s.cfg.Events.BatchSize, s.cfg.Events.FlushInterval)

	// Build the proxy handler with configured thresholds.
	p := proxy.NewWithOAuthPoolRuntime(vaultReader, registry, providers, collector, s.ctx, s.oauthPoolRuntime)
	// Stamp the generation identity FIRST and unconditionally. Every runtime
	// counter this Proxy exposes on /v1/diagnostics/pipeline is scoped to this
	// generation — a reload swaps the *Proxy behind an unchanged PID, so the
	// counters silently restart at zero. Publishing the ID is what lets an
	// external reader notice the reset (health-signal-surface). It must not ride
	// on SetReporter: that call is skipped entirely when neither a collector nor
	// a WAL is configured, i.e. exactly the offline deployments that have the
	// fewest other ways to see a reload.
	p.SetGenerationID(int64(id))
	// Inject the shared, supervisor-owned routing-override cache (I-side §6.5) so
	// the group-route hot path can read the engine's seat→account redirects.
	// Unconditional + nil-safe: an empty cache (no team cred / control URL / poll
	// not landed) just means every request uses the local seatassign pick.
	p.SetRoutingOverrides(s.routingOverrides)
	// The license forwarding gate. Supervisor-scoped on purpose: handing each
	// generation a fresh cache would let every reload forward again for one poll
	// interval, and `aikey key sync` triggers reloads.
	p.SetLicensePlane(s.licensePlane)
	// Whole-account cooldown changes happen on the request hot path. The hook is
	// deliberately a non-blocking channel kick; SQLite restamping runs in the
	// supervisor-owned worker and can never delay the upstream response.
	p.SetPoolCooldownChangeHook(s.requestCurrentRoutedRestamp)
	// Local console base for member-login URLs in group login-required 401s
	// (20260703 update). Explicitly-empty (cluster/server configs) → URL-less
	// fallback; absent key (pre-20260703 preserved configs) → default 8090.
	p.SetConsoleURL(s.cfg.ResolvedConsoleURL())
	// 🔴 A cluster NODE must not serve the path-prefix branch to a caller that
	// names no virtual key. Wired from cluster.enabled — the same single value
	// config.validate() uses to lift the loopback rail, so the two decisions can
	// never disagree about what this process is. See proxy.SetClusterNode and
	// workflow/CI/bugfix/2026-09-02-集群节点代理是一个公网开放中继.md.
	p.SetClusterNode(s.cfg.Cluster.Enabled)
	// SyncRail §5.4: let the 401 wording distinguish "you need to sign in" from
	// "the assignment rail is unreachable so this pick may be misdirected".
	p.SetRoutingRailHealth(func() (string, int64) { return s.railHealthFor("routing_override") })
	p.SlowRequestMs = int64(s.cfg.Log.SlowRequestMs)
	p.VerySlowRequestMs = int64(s.cfg.Log.VerySlowRequestMs)
	// Supervisor-owned runtime state is applied atomically with active.Store by
	// activateGeneration. Reading it here would recreate the stale-build window.
	// Phase 2 Stage 3: wire the token-quota gate from the per-process snapshot +
	// counter (both supervisor-scoped so the counter survives 5s syncs/reloads).
	// nil-safe + flag-gated inside the enforcer — a no-op when PROXY_QUOTA_ENABLED
	// is off, so the request path is unchanged unless quota is explicitly on.
	enf := quota.NewEnforcer(s.quotaSnapshot, s.quotaCounter, s.quotaEnabled)
	// D-U7/P9 enforce_mode=budget (deployment-level): strict customers fail-closed
	// on a stale baseline; default availability never does (offline-first).
	if budget, maxStale := quotaBudgetModeFromEnv(); budget {
		enf.SetBudgetMode(maxStale)
		slog.Info("quota.enforce_mode.budget_enabled", "max_staleness_seconds", int(maxStale.Seconds()))
	}
	p.SetQuotaEnforcer(enf)

	// Conversation-audit (enterprise Cluster): inject the capture observer's
	// deps BEFORE buildObserverRegistry, because the framework reads observer
	// deps at BuildObservers time. Gated on a team collector destination
	// (route or credential — see the gate below) — a Personal/offline
	// deployment passes empty Deps (nil sink), so the observer build() skips it
	// and pays nothing. The sink is attached to the real content outbox later
	// in this same pass (after the usage reporter block, where the optional team
	// credential is built). See conversation_audit_wiring.go.
	var convAuditSink *conversationAuditSink
	// Wire for TEAM/CLUSTER deployments. Signal = a "team" collector
	// destination (route OR credential), NOT the credential alone. The Cluster
	// worker proxy reports to the internal collector over network trust with NO
	// collector_credentials["team"] — only a collector_routes["team"] URL. The
	// usage reporter handles that nil-credential case by sending without an
	// Authorization header (and ContentReporter.doUpload does the same), so the
	// old credential-only gate silently excluded the Cluster edition — the very
	// edition this feature targets. Personal/offline (no team route/cred) still
	// wires nothing. The org-policy gate (Enabled, below) independently controls
	// whether a wired observer actually captures.
	_, hasTeamCred := s.cfg.Events.CollectorCredentials["team"]
	hasTeamRoute := s.cfg.Events.CollectorRoutes["team"] != ""
	if s.cfg.Events.CollectorURL != "" && (hasTeamCred || hasTeamRoute) {
		convAuditSink = newConversationAuditSink(slog.Default())
		conversation_audit.SetDeps(conversation_audit.Deps{
			Sink:    convAuditSink,
			Enabled: s.ConversationAuditEnabled,
			// Adapt int64 policy accessor → observer's func() int cap (the
			// content cap is small; the conversion is safe).
			MaxBytes: func() int { return int(s.ConversationAuditMaxBytes()) },
		})
	} else {
		conversation_audit.SetDeps(conversation_audit.Deps{}) // nil sink → observer not built this gen
	}

	// Phase 4 M2: build the per-generation observer registry. Skipped when
	// no observer descriptors are registered (e.g. proxy build without the
	// rhythm plugin blank-imported in main.go); in that path SetObserver
	// is never called and Notify* hooks are zero-cost no-ops at request
	// time. See pkg/observer/registry.go for the registration contract.
	p.SetObserverRegistry(buildObserverRegistry(vaultReader, s.cfg.Observers, slog.Default()))

	// P4 filter dispatcher (was the P3 fail-loud 501 stub). Decides whether
	// this generation runs a compliance/DLP filter child and spawns it, wiring
	// it into p via SetFilterHook. On spawn failure or a vault declaration we
	// can't honor, it flips the proxy to fail-loud 501 instead (anti-example F:
	// never silently pass traffic through an unrunnable filter). The returned
	// child is stored in the generation so it's Shutdown on reload-drain. The
	// check is per-generation (cheap), so a vault/env change re-evaluates on
	// next Reload. See filter_hook.go + SPEC §1.5.7 / §6.6.
	filterHook := s.installFilterHook(p, vaultReader)
	// Record the filter-app signature this generation was built with so
	// syncManagedKeys can detect a later enable/disable and trigger a reload.
	if baseSig, ok := computeFilterSig(vaultReader); ok {
		sig := filterSigWithPasswordTier(filterSigWithPrivacyTier(baseSig, s.masterPrivacyTier.Load()), s.masterPasswordTierAdvanced.Load())
		s.lastFilterSig.Store(&sig)
	}

	// Create the local WAL writer unconditionally whenever WALDir is set.
	// This is the canonical event log used by `aikey statusline` / `aikey watch`,
	// and it must exist even in standalone (no collector_url) deployments —
	// the reporter is only one of several consumers.  When the reporter is
	// also created below we hand it this shared instance so there is only a
	// single writer touching the directory.
	var sharedWAL *events.WALWriter
	var seqAlloc *events.LaneAllocator
	// Signal reporting needs a stable source even when usage WAL/reporting is
	// disabled. Cluster's declared node_id is authoritative; member Proxies reuse
	// the vault source identity and safely fall back to authenticated account scope.
	sourceID, _ := vault.ReadConfigString(s.cfg.Vault.Path, SourceIdentityKey)
	if s.cfg.Cluster.Enabled && s.cfg.Cluster.NodeID != "" {
		sourceID = s.cfg.Cluster.NodeID
	}
	if s.cfg.Events.WALDir != "" {
		if w, werr := events.NewWALWriter(s.cfg.Events.WALDir); werr != nil {
			slog.Warn("local wal init failed, offline usage log disabled", "error", werr)
		} else {
			sharedWAL = w
			// Always attach to proxy.  When reporter is nil this is the only
			// sink; when reporter is non-nil the proxy skips direct append
			// (reporter.Report handles it via the shared instance).
			p.SetWAL(sharedWAL)

			// Delivery integrity: build the reserve-ahead sequence allocator
			// (state file next to the WAL) and read the vault's stable source
			// identity, then wire both into the proxy so reportUsage can stamp
			// source_id / source_seq. Failures degrade to v1-shaped events
			// (no seq) rather than blocking the proxy — usage still flows, it
			// just doesn't participate in server gap detection until fixed.
			seqStatePath := filepath.Join(s.cfg.Events.WALDir, seqStateFile)
			// Per-lane from 2026-08-21: one dense stream per org, because the
			// server accounts per (org, source). seqStatePath's directory is
			// the WAL dir; the legacy single-stream file in it is preserved and
			// used as the floor every lane starts above (never-reuse survives
			// the split). Construction cannot fail — lanes are created lazily,
			// so a bad state file surfaces on first use, per lane.
			_ = seqStatePath
			if sa := events.NewLaneAllocator(s.cfg.Events.WALDir, events.DefaultSeqBlockSize); sa != nil {
				seqAlloc = sa
				if sourceID == "" {
					slog.Warn("source_identity missing from vault; events emitted without source_id",
						"event.name", "usage.source_identity.missing")
				}
			}
			// Thread proxy identity fields that reportUsage needs even in
			// the offline path.  SetReporter below would overwrite these
			// with the same values when a reporter is present.
			var loadedSeq int64
			if seq, err := vault.ReadConfigU64LE(s.cfg.Vault.Path, VaultChangeSeqKey); err == nil && seq <= math.MaxInt64 {
				loadedSeq = int64(seq)
			}
			p.SetReporter(nil, fmt.Sprintf("proxy-%d", id), s.version, proxy.GenerationLabel(int64(id)), loadedSeq, vaultReader.GetLoggedInAccountID())
		}
	}
	// One wiring point for both usage-event identity and allocation-signal source.
	p.SetDeliveryIntegrity(sourceID, seqAlloc)

	// Attach usage reporter if any upload destination is configured —
	// either the legacy single CollectorURL, or at least one non-empty
	// per-route entry under CollectorRoutes (added 2026-05-10 for
	// personal/team isolation). See roadmap update 20260510-personal-team-
	// 数据隔离与合并显示.md.
	var reporter *events.Reporter
	var canary *events.CanaryProbe
	// Conversation-audit content outbox, assigned inside the hasAnyURL block
	// below (where the team credential is built) and handed to the generation
	// for teardown. nil unless this is a wired team deployment.
	var contentWAL *events.ContentWAL
	var contentSeqAlloc *events.SeqAllocator
	var contentReporter *events.ContentReporter
	hasAnyURL := s.cfg.Events.CollectorURL != ""
	for _, u := range s.cfg.Events.CollectorRoutes {
		if u != "" {
			hasAnyURL = true
			break
		}
	}
	if hasAnyURL {
		// 2026-05-11 B4 phase: build per-RouteSource Credentials from the
		// user-layer config.collector_credentials block. Today only the
		// "team" route is wired (user JWT with auto-refresh against
		// control-service). Personal / OAuth routes fall through to the
		// legacy CollectorToken inside reporter — no change in behavior.
		//
		// refresh_token is read directly from the vault's platform_account
		// table (proxy already holds the master-derived key for vault
		// access). Construction errors are non-fatal: an absent or partial
		// credential just leaves the team route credential-less, which the
		// reporter handles by falling back to CollectorToken.
		credentials := buildCollectorCredentials(
			s.cfg.Events.CollectorCredentials,
			vaultReader,
		)

		var err error
		reporter, err = events.NewReporter(&events.ReporterConfig{
			CollectorURL:              s.cfg.Events.CollectorURL,
			CollectorRoutes:           s.cfg.Events.CollectorRoutes,
			CollectorRouteCredentials: credentials,
			CollectorToken:            s.cfg.Events.CollectorToken,
			QueueCapacity:             s.cfg.Events.QueueCapacity,
			BatchSize:                 s.cfg.Events.UploadBatchSize,
			UploadInterval:            s.cfg.Events.UploadInterval,
			WALDir:                    s.cfg.Events.WALDir,
			SharedWAL:                 sharedWAL,
			SeqAlloc:                  seqAlloc, // may be nil; reporter only READS Allocated() for tail-gap detection
			SourceID:                  sourceID, // for D2.5/D3 audit: filter completeness to "my" source
			ProxyInstanceID:           fmt.Sprintf("proxy-%d", id),
			ConfigHash:                s.cfg.PipelineConfigHash(),
			DBPath:                    s.cfg.Events.DBPath,
		})
		if err != nil {
			slog.Warn("reporter init failed, usage reporting disabled", "error", err)
			reporter = nil
		} else {
			var loadedSeq int64
			if seq, err := vault.ReadConfigU64LE(s.cfg.Vault.Path, VaultChangeSeqKey); err == nil && seq <= math.MaxInt64 {
				loadedSeq = int64(seq)
			}
			p.SetReporter(reporter, fmt.Sprintf("proxy-%d", id), s.version, proxy.GenerationLabel(int64(id)), loadedSeq, vaultReader.GetLoggedInAccountID())
			slog.Info("usage reporter enabled", "collector_url", s.cfg.Events.CollectorURL)

			// Start canary probe. As of 2026-04-17 diagnostics live on the
			// collector-service (/v1/diagnostics/pipeline, /internal/canary-check),
			// not the control plane. Prefer CollectorURL; fall back to
			// ControlURL for backward compatibility with older trial configs
			// where control_url was set and collector_url was not.
			//
			// QueryURL, when configured, enables the query-stage probe so the
			// canary covers the full ODS → projector-ack → query chain. Trial
			// deployments typically leave it empty (single-port, shared DB).
			diagURL := s.cfg.Events.CollectorURL
			if diagURL == "" {
				diagURL = s.cfg.Events.ControlURL
			}
			canary = events.NewCanaryProbe(reporter, events.CanaryConfig{
				DiagnosticsURL: diagURL,
				QueryURL:       s.cfg.Events.QueryURL,
			})
		}

		// Conversation-audit content outbox — wired here (inside hasAnyURL, so
		// the team `credentials` built above are in scope), independent of the
		// usage reporter's success: content has its own WAL + reporter. Prefer a
		// per-route team URL; fall back to the legacy single CollectorURL.
		if convAuditSink != nil {
			convCollectorURL := s.cfg.Events.CollectorRoutes["team"]
			if convCollectorURL == "" {
				convCollectorURL = s.cfg.Events.CollectorURL
			}
			// credentials["team"] is the per-route team JWT (Personal/lobster,
			// from vault); CollectorToken is the cluster-node static service
			// token (cluster worker nodes have no team credential). The content
			// reporter tries the credential then the token — mirrors the usage
			// reporter, so cluster-node uploads authenticate (else 401).
			contentWAL, contentSeqAlloc, contentReporter = wireConversationAudit(
				s.cfg.Events.WALDir, convCollectorURL, sourceID,
				fmt.Sprintf("proxy-%d", id), credentials["team"], s.cfg.Events.CollectorToken,
				convAuditSink, slog.Default(),
			)
		}
	}

	// Allocation/account signal reporting is independent of usage reporting. A
	// cluster worker commonly has no member JWT and may also have no collector
	// destination; neither condition may suppress a hard-revoked member-token
	// transition. Cluster uses the existing org-pinned service credential; other
	// editions reuse the live team account JWT used by the group-runtime rails.
	// Store the desired configuration on the generation and apply it only at the
	// activation boundary; a generation that fails to build cannot disturb the
	// current process-owned reporter.
	masterURL := readControlPanelURL()
	signalCfg := signalReportingConfig{}
	if s.cfg.Cluster.Enabled && s.cfg.Cluster.OrgID != "" && s.cfg.Cluster.ControlServiceToken != "" {
		signalCfg = signalReportingConfig{
			mode: signalReportingOrg, controlURL: masterURL,
			orgID: s.cfg.Cluster.OrgID, serviceToken: s.cfg.Cluster.ControlServiceToken,
		}
	} else if signalURL, bearer := signalReportingAuth(masterURL, s.teamCred, s.signalRefreshToken); bearer != nil {
		signalCfg = signalReportingConfig{mode: signalReportingMember, controlURL: signalURL, bearer: bearer}
	}

	// Only hand the WAL to the generation when nobody else closes it. If a
	// reporter was attached it owns (and closes) the shared writer — passing
	// it here too would double-close on reload.
	var ownedWAL *events.WALWriter
	if reporter == nil {
		ownedWAL = sharedWAL
	}

	gen := &generation{
		id:              id,
		vaultPath:       s.cfg.Vault.Path,
		vault:           vaultReader,
		registry:        registry,
		providers:       providers,
		proxy:           p,
		collector:       collector,
		eventStore:      eventStore,
		reporter:        reporter,
		canary:          canary,
		filterHook:      filterHook,
		standaloneWAL:   ownedWAL,
		seqAlloc:        seqAlloc,
		contentReporter: contentReporter,
		contentWAL:      contentWAL,
		signalReporting: signalCfg,
		contentSeqAlloc: contentSeqAlloc,
		drained:         make(chan struct{}),
	}

	// Load quota rules for this generation's vault at startup / reload (the 5s
	// sync only fires on a later seq advance). Fault-isolated — see helper.
	s.reloadQuotaSnapshot(gen)

	return gen, nil
}

// Listen creates and returns the TCP listener with automatic port-drift
// fallback. Per 20260430-端口偏移能力修复.md, when the configured port is
// occupied (EADDRINUSE) the listener retries port+1, port+2, ..., up to
// port+cfg.Listen.PortDriftMax. The caller should hold the listener for the
// lifetime of the process and pass it to http.Server.Serve so the port is
// never released during reloads.
//
// Returned values:
//   - ln: the bound listener
//   - configuredAddr: cfg.Listen.Addr() (the originally requested address)
//   - actualAddr: ln.Addr().String() (may differ from configuredAddr after drift)
//   - driftOffset: actual port - configured port (0 when no drift occurred)
//
// driftMax < 0 disables drift entirely (strict legacy: fail on first
// EADDRINUSE). driftMax == 0 is honored by config.applyDefaults() — yaml
// "port_drift_max: 0" gets coerced to DefaultPortDriftMax.
func Listen(cfg *config.Config) (ln net.Listener, configuredAddr, actualAddr string, driftOffset int, err error) {
	host := cfg.Listen.Host
	port := cfg.Listen.Port
	configuredAddr = cfg.Listen.Addr()

	driftMax := cfg.Listen.PortDriftMax
	if driftMax < 0 {
		driftMax = 0
	}

	var lastErr error
	for offset := 0; offset <= driftMax; offset++ {
		candidate := fmt.Sprintf("%s:%d", host, port+offset)
		l, lerr := net.Listen("tcp", candidate)
		if lerr == nil {
			return l, configuredAddr, candidate, offset, nil
		}
		if !isAddrInUse(lerr) {
			return nil, configuredAddr, "", 0, fmt.Errorf("listen on %s: %w", candidate, lerr)
		}
		lastErr = lerr
	}
	return nil, configuredAddr, "", 0, fmt.Errorf(
		"port drift exhausted: %s:%d..%d all occupied (last error: %w)",
		host, port, port+driftMax, lastErr,
	)
}

// isAddrInUse returns true when err is "address already in use" — the
// signal that drift should retry the next port.
func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		if errors.Is(sysErr.Err, syscall.EADDRINUSE) {
			return true
		}
	}
	// Cross-platform message-text fallback: macOS/Linux phrase + Windows phrase.
	msg := err.Error()
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "Only one usage of each socket address")
}

// refreshTokenSource is the minimal vault contract buildCollectorCredentials
// depends on. Defined here (not in vault/) so tests can pass a stub
// without spinning up a real SQLite vault. *vault.Reader satisfies it
// via its GetPlatformRefreshToken method.
type refreshTokenSource interface {
	GetPlatformRefreshToken() (string, error)
}

// buildCollectorCredentials turns the yaml-merged collector_credentials
// map into the events.Credential map the reporter consumes. Today only
// `type: jwt` is recognized; future types (mTLS material, OAuth client
// creds for non-aikey backends, etc.) extend this switch.
//
// The refresh_token comes from vault, not yaml — see
// vault.Reader.GetPlatformRefreshToken for the rationale.
//
// Returns nil when no credentials are configured. Reporter handles a
// nil map by falling back to the legacy CollectorToken global, so an
// unconfigured deployment keeps working unchanged.
func buildCollectorCredentials(
	cfgCreds map[string]config.CollectorCredential,
	vaultReader refreshTokenSource,
) map[string]events.Credential {
	if len(cfgCreds) == 0 {
		return nil
	}
	out := make(map[string]events.Credential, len(cfgCreds))

	for routeSource, c := range cfgCreds {
		switch c.Type {
		case "jwt":
			refreshToken, err := vaultReader.GetPlatformRefreshToken()
			if err != nil {
				slog.Warn(
					"collector credential: skip route — vault refresh_token read failed",
					"event.name", "credential.bootstrap.vault_read_failed",
					"route_source", routeSource,
					"error.message", err.Error(),
				)
				continue
			}
			if refreshToken == "" {
				// platform_account row missing OR refresh_token NULL.
				// Pre-login state; quietly skip so reporter falls back
				// to legacy CollectorToken. Once `aikey account login`
				// runs, refresh_token populates and a proxy reload picks
				// it up.
				slog.Info(
					"collector credential: skip route — no vault refresh_token (pre-login)",
					"event.name", "credential.bootstrap.no_refresh_token",
					"route_source", routeSource,
				)
				continue
			}
			if c.Token == "" || c.RefreshURL == "" {
				slog.Warn(
					"collector credential: skip route — yaml bundle incomplete",
					"event.name", "credential.bootstrap.yaml_incomplete",
					"route_source", routeSource,
					"missing_token", c.Token == "",
					"missing_refresh_url", c.RefreshURL == "",
				)
				continue
			}
			out[routeSource] = &events.RefreshableJWT{
				AccessToken:  c.Token,
				RefreshToken: refreshToken,
				ExpiresAt:    time.Unix(c.ExpiresAt, 0),
				RefreshURL:   c.RefreshURL,
				// PersistFn is intentionally nil: the proxy doesn't write
				// back to user.yaml on each refresh — that's the CLI's
				// responsibility on the next `aikey account login` /
				// `aikey use` cycle. Leaving the new access_token only
				// in-memory means a proxy restart re-reads the older
				// (possibly stale) yaml value and the first Bearer()
				// triggers another refresh — safe, idempotent, and keeps
				// the file-write trust boundary unchanged.
			}
			slog.Info(
				"collector credential: route wired (jwt)",
				"event.name", "credential.bootstrap.wired",
				"route_source", routeSource,
				"refresh_url", c.RefreshURL,
				"access_expires_at", c.ExpiresAt,
			)

		default:
			slog.Warn(
				"collector credential: unknown type, skipping",
				"event.name", "credential.bootstrap.unknown_type",
				"route_source", routeSource,
				"type", c.Type,
			)
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// signalReportingAuth returns the control-plane endpoint and bearer source used
// by Proxy's allocation-engine signal reporter. It deliberately reuses the
// railSet's teamCredentialSource instead of the usage reporter's legacy
// collector_credentials bundle: group runtime, routing overrides, and signals
// are three views of the same team control plane and must share one auth source.
// The master URL is captured with the closure so a request can never mint a token
// for one server and POST it to another. A settings/control-URL change rebuilds
// the Proxy generation and therefore this pair.
func signalReportingAuth(
	masterURL string,
	teamCred *teamCredentialSource,
	vaultReader refreshTokenSource,
) (string, func(context.Context) (string, error)) {
	if masterURL == "" || teamCred == nil || vaultReader == nil {
		return "", nil
	}
	return masterURL, func(ctx context.Context) (string, error) {
		return teamCred.bearer(ctx, vaultReader, masterURL)
	}
}

// BindingCooldownSnapshot exposes the active generation's binding-axis cooldown
// state for /status (task 3.4).
func (s *Supervisor) BindingCooldownSnapshot() map[string]int {
	gen := s.active.Load()
	if gen == nil || gen.proxy == nil {
		return nil
	}
	return gen.proxy.BindingCooldownSnapshot()
}

// FallbackSwitches is the active generation's upstream-switch counter (task 3.6).
func (s *Supervisor) FallbackSwitches() int64 {
	gen := s.active.Load()
	if gen == nil || gen.proxy == nil {
		return 0
	}
	return gen.proxy.FallbackSwitches()
}
