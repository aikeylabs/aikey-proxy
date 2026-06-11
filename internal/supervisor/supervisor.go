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
	"net"
	"net/http"
	"os"
	"strconv"
	"path/filepath"
	"sort"
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
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/apppipe"
	"github.com/AiKeyLabs/aikey-proxy/internal/quota"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/aikey-proxy/pkg/heartbeat"
)

// providerToProtocol maps a provider code to its proxy protocol name.
// Duplicated from proxy/middleware.go (unexported) to avoid cross-package dependency.
func providerToProtocol(providerCode string) string {
	switch strings.ToLower(providerCode) {
	case "anthropic", "claude":
		return "anthropic"
	default:
		return "openai_compatible"
	}
}

// providerDefaultBaseURL returns the default upstream base URL for a provider.
// Duplicated from proxy/middleware.go (unexported).
func providerDefaultBaseURL(providerCode string) string {
	switch strings.ToLower(providerCode) {
	case "anthropic", "claude":
		return "https://api.anthropic.com"
	case "openai", "gpt", "chatgpt":
		return "https://api.openai.com/v1"
	case "google", "gemini":
		return "https://generativelanguage.googleapis.com"
	// 2026-05-08 Kimi 双平台拆分: kimi/moonshot 拆 case (pre-split 共用 case
	// 错误地把 moonshot 路由到 Kimi Code endpoint)。'kimi' 为 deprecated alias。
	case "kimi_code", "kimi":
		return "https://api.kimi.com/coding"
	case "moonshot":
		return "https://api.moonshot.cn"
	case "deepseek":
		return "https://api.deepseek.com/v1"
	default:
		return ""
	}
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
	id         int
	vaultPath  string
	vault      *vault.Reader
	registry   *vkeys.Registry
	providers  *provider.Registry
	proxy      *proxy.Proxy
	collector  *events.Collector
	eventStore *events.Store
	reporter   *events.Reporter      // usage reporter (nil when collector_url is not configured)
	canary     *events.CanaryProbe  // synthetic canary probe (nil when reporter or control_url is not configured)
	filterHook apphook.FilterTarget  // P4 compliance/DLP filter (single child or M-process pool; nil when no filter app is active)

	// standaloneWAL is only populated when this generation created the
	// local WAL writer AND no reporter consumed it — i.e. collector_url is
	// empty. When a reporter is present it owns the WAL and its Close()
	// closes it, so we leave standaloneWAL nil to avoid double-close. This
	// split is what keeps `generation.close()` from leaking file handles
	// on every reload in offline/standalone deployments.
	standaloneWAL *events.WALWriter

	// seqAlloc is the delivery-integrity sequence allocator for this generation.
	// Closed in close() so a graceful shutdown shrinks the persisted high-water
	// mark to the actual last-used seq (zero seq burn on the common restart
	// path; only a hard crash leaves a bounded auditable gap). nil when no WAL.
	seqAlloc *events.SeqAllocator

	// Drain tracking: incremented when a request enters Handle, decremented on exit.
	inflight atomic.Int64
	draining atomic.Bool
	drained  chan struct{} // closed when inflight reaches 0 after draining is set
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

// close releases all resources held by this generation.
func (g *generation) close() {
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
	cfg        *config.Config
	configPath string // path to the YAML config file, re-read on reload
	password   string
	version    string // build version, passed to proxy for audit metadata

	transport http.RoundTripper // optional upstream proxy transport; nil = default
	broker    proxy.OAuthBroker // OAuth broker (set via SetBroker); nil = OAuth disabled

	active    atomic.Pointer[generation]
	reloadMu  sync.Mutex // serialize concurrent reload requests
	genID     atomic.Int64
	startedAt time.Time

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

	// masterCompliance is the org-level compliance master switch polled from the
	// control backend (G3). The supervisor is the LIFECYCLE owner of the
	// compliance detector: the app pulls its own packs, but whether it runs at
	// all is decided here. true → force-spawn the detector even when the user's
	// local filter_stages is NULL (master mandate); the user's local toggle still
	// governs when this is false. Polled by pollComplianceMasterPolicy.
	masterCompliance atomic.Bool

	// Enterprise quota (Phase 2 Stage 2 — design §0.5/§5.2). Snapshot + counter
	// live on the supervisor (not per-generation) so the counter accumulates
	// continuously across 5s syncs and /admin/reload; the snapshot is gen-swapped
	// on each vault-seq advance. quotaEnabled gates LOADING only (off = the
	// rule-distribution rail is fully bypassed, proxy == pre-quota behavior).
	// Stage 2 only loads + counts; request interception is Stage 3.
	quotaEnabled  bool
	quotaSnapshot *quota.Snapshot
	quotaCounter  *quota.Counter
	// quotaIncrementSeeded guards the one-time restore of persisted local
	// increments (quota_local_usage, P0) into the counter at startup. Seeding is a
	// SET before any accrual; re-running would clobber in-flight increments, so it
	// fires exactly once (first reloadQuotaSnapshot, in buildGeneration, before
	// serving). Later reloads only re-seed baselines.
	quotaIncrementSeeded bool
	// quotaHeartbeat is the traffic-independent server-reachability probe behind
	// budget-mode staleness (D-U7/P9). nil unless enforce_mode=budget AND a
	// collector URL is configured — so the default availability path (and Personal)
	// adds NO periodic server call (offline-first preserved). The 5s sync copies its
	// LastOKAt into the snapshot for budgetStale.
	quotaHeartbeat *heartbeat.Probe

	// ctx / cancel bound the lifetime of all detached upstream calls.
	// Canceled in Shutdown() to stop any in-flight upstream requests.
	ctx    context.Context
	cancel context.CancelFunc
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
		cfg:           cfg,
		configPath:    configPath,
		password:      password,
		version:       version,
		startedAt:     time.Now(),
		ctx:           ctx,
		cancel:        cancel,
		quotaEnabled:  quotaEnabledFromEnv(),
		quotaSnapshot: quota.NewSnapshot(),
		quotaCounter:  quota.NewCounter(),
	}
	gen, err := s.buildGeneration()
	if err != nil {
		return nil, fmt.Errorf("initial generation failed: %w", err)
	}
	s.active.Store(gen)
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

	// G3: poll the org-level compliance master switch so an enterprise can mandate
	// compliance from the control backend (force-spawn the detector regardless of
	// the user's local toggle). No-op when no team/org is configured (Personal).
	observability.GoSafe("supervisor.compliance_policy_poll", observability.Isolated, func() { s.pollComplianceMasterPolicy(s.ctx) })

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
	client := &http.Client{Timeout: 5 * time.Second}
	s.quotaHeartbeat = heartbeat.New(interval, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
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

// SetTransport sets the outbound RoundTripper used by all generations.
// Must be called before any requests are served (right after New).
// SetBroker sets the OAuth broker for all proxy generations.
func (s *Supervisor) SetBroker(b proxy.OAuthBroker) {
	s.broker = b
	if gen := s.active.Load(); gen != nil {
		gen.proxy.SetBroker(b)
	}
}

func (s *Supervisor) SetTransport(t http.RoundTripper) {
	s.transport = t
	// Also apply to the already-running initial generation.
	if gen := s.active.Load(); gen != nil {
		gen.proxy.SetTransport(t)
	}
}

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

// computeFilterSig returns a stable signature of the vault's current filter-app
// set (sorted, comma-joined slugs). ok=false on read error so the caller skips
// the comparison rather than mistaking an error for a "set changed" → reload storm.
func computeFilterSig(vaultReader *vault.Reader) (string, bool) {
	slugs, err := vaultReader.GetFilterAppSlugs()
	if err != nil {
		return "", false
	}
	sort.Strings(slugs)
	// R9: fold each slug's filter_record_allow into the signature so a settings
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
		parts = append(parts, fmt.Sprintf("%s:%t", s, ra))
	}
	return strings.Join(parts, ","), true
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
	if newSig, ok := computeFilterSig(gen.vault); ok {
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
			if err := s.Reload(s.ctx); err != nil {
				slog.Warn("managed key sync: filter-triggered reload failed; "+
					"continuing with lightweight sync (filter unchanged)", "error", err)
				// fall through — do NOT return — so the cred path below still runs.
			} else {
				return // Reload rebuilt registry + filter hook + advanced loaded_seq.
			}
		}
	}

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
	}
	for _, mk := range managedKeys {
		// 2026-04-29 prefix rename: team token = aikey_team_<vk_id>.
		// Use NormalizeTeamToken so historical-prefix dirty data in
		// mk.VirtualKeyID gets stripped+rebuilt (defense-in-depth: should
		// be bare vk_id in cache, but we don't trust it). Empty vk_id is
		// upstream bug — log warning and skip the row rather than register
		// a degenerate "aikey_team_" token.
		token, err := NormalizeTeamToken(mk.VirtualKeyID)
		if err != nil {
			slog.Warn("managed key sync: skip team key with invalid vk_id",
				"vk_id", mk.VirtualKeyID,
				"credential_id", mk.CredentialID,
				"error", err.Error(),
			)
			continue
		}
		allRoutes[token] = managedKeyToRoute(mk)
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
			"total_routes", len(allRoutes),
			"vault_seq", vaultSeq,
		)
	}
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
// org-less proxies see zero behaviour change; only a confirmed over-limit
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
func (s *Supervisor) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
// /admin/metrics exposes both billing-loss paths.
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

// GetKeyCheckTargets resolves the active key's decrypted credentials for each
// provider it supports. Used by GET /health/keys to probe key validity.
// Returns nil (no error) when no key is active.
func (s *Supervisor) GetKeyCheckTargets() ([]admin.KeyCheckTarget, error) {
	gen := s.active.Load()
	if gen == nil {
		return nil, nil
	}
	cfg, err := gen.vault.GetActiveKeyConfig()
	if err != nil || cfg == nil {
		return nil, nil
	}

	var targets []admin.KeyCheckTarget
	switch cfg.KeyType {
	case "team":
		for _, providerCode := range cfg.Providers {
			mk, err := gen.vault.GetActiveTeamKeyByProvider(providerCode)
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
						"provider", providerCode,
						"error", err,
					)
				}
				continue
			}
			baseURL := mk.BaseURL
			if baseURL == "" {
				if u, ok := mk.ProviderBaseURLs[providerCode]; ok && u != "" {
					baseURL = u
				}
			}
			targets = append(targets, admin.KeyCheckTarget{
				Provider: providerCode,
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
			// Each provider may have its own default base URL; use the stored URL if set
			// (custom gateways share one URL across all protocols).
			burl := baseURL
			if burl == "" {
				burl = personalProviderBaseURL(pcode)
			}
			targets = append(targets, admin.KeyCheckTarget{
				Provider: pcode,
				Protocol: providerProtocol(pcode),
				BaseURL:  burl,
				APIKey:   plaintext,
				KeyRef:   cfg.KeyRef,
			})
		}
	}
	return targets, nil
}

// personalProviderBaseURL returns the default upstream base URL for a known provider code.
// Used when a personal key entry has no custom base_url stored.
func personalProviderBaseURL(code string) string {
	switch strings.ToLower(code) {
	case "anthropic", "claude":
		return "https://api.anthropic.com"
	case "openai":
		return "https://api.openai.com/v1"
	case "google", "gemini":
		return "https://generativelanguage.googleapis.com"
	// 2026-05-08 Kimi 双平台拆分(同 supervisor.providerDefaultBaseURL)
	case "kimi_code", "kimi":
		return "https://api.kimi.com/coding"
	case "moonshot":
		return "https://api.moonshot.cn"
	case "deepseek":
		return "https://api.deepseek.com/v1"
	default:
		return ""
	}
}

// providerProtocol maps a provider code to its auth/wire protocol name.
func providerProtocol(code string) string {
	switch strings.ToLower(code) {
	case "anthropic", "claude":
		return "anthropic"
	case "google", "gemini":
		return "google"
	default:
		return "openai"
	}
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

	// Swap to new generation — new requests go to newGen from this point.
	s.active.Store(newGen)
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

	return nil
}

// Shutdown drains the active generation and closes all resources.
func (s *Supervisor) Shutdown(timeout time.Duration) {
	// Cancel the proxy lifecycle context to abort any detached upstream calls.
	s.cancel()
	gen := s.active.Load()
	slog.Info("supervisor shutting down", "generation_id", gen.id)
	gen.drain(timeout, "shutdown")
	gen.close()
}

// buildGeneration creates a fully-initialized generation ready to handle requests.
func (s *Supervisor) buildGeneration() (*generation, error) {
	id := int(s.genID.Add(1))

	// Open vault.
	vaultReader, err := vault.Open(s.cfg.Vault.Path, s.password)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}

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
	if managedKeys, err := vaultReader.GetActiveManagedKeys(); err != nil {
		slog.Warn("could not load managed virtual keys", "error", err)
	} else if len(managedKeys) > 0 {
		managedRoutes := make(map[string]*vkeys.ResolvedRoute, len(managedKeys))
		for _, mk := range managedKeys {
			token, terr := NormalizeTeamToken(mk.VirtualKeyID)
			if terr != nil {
				slog.Warn("buildGeneration: skip team key with invalid vk_id",
					"vk_id", mk.VirtualKeyID,
					"credential_id", mk.CredentialID,
					"error", terr.Error(),
				)
				continue
			}
			managedRoutes[token] = managedKeyToRoute(mk)
		}
		registry.Merge(managedRoutes)
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
	p := proxy.New(vaultReader, registry, providers, collector, s.ctx)
	p.SlowRequestMs = int64(s.cfg.Log.SlowRequestMs)
	p.VerySlowRequestMs = int64(s.cfg.Log.VerySlowRequestMs)
	if s.transport != nil {
		p.SetTransport(s.transport)
	}
	if s.broker != nil {
		p.SetBroker(s.broker)
	}
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
	if sig, ok := computeFilterSig(vaultReader); ok {
		s.lastFilterSig.Store(&sig)
	}

	// Create the local WAL writer unconditionally whenever WALDir is set.
	// This is the canonical event log used by `aikey statusline` / `aikey watch`,
	// and it must exist even in standalone (no collector_url) deployments —
	// the reporter is only one of several consumers.  When the reporter is
	// also created below we hand it this shared instance so there is only a
	// single writer touching the directory.
	var sharedWAL *events.WALWriter
	var seqAlloc *events.SeqAllocator
	var sourceID string // vault source identity; reused for SetDeliveryIntegrity + ReporterConfig.SourceID
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
			if sa, serr := events.NewSeqAllocator(seqStatePath, events.DefaultSeqBlockSize); serr != nil {
				slog.Warn("seq allocator init failed, events emitted without source_seq",
					"event.name", "usage.seqalloc.init_failed", "error", serr)
			} else {
				seqAlloc = sa
				sourceID, _ = vault.ReadConfigString(s.cfg.Vault.Path, SourceIdentityKey)
				if sourceID == "" {
					slog.Warn("source_identity missing from vault; events emitted without source_id",
						"event.name", "usage.source_identity.missing")
				}
				p.SetDeliveryIntegrity(sourceID, seqAlloc)
			}
			// Thread proxy identity fields that reportUsage needs even in
			// the offline path.  SetReporter below would overwrite these
			// with the same values when a reporter is present.
			var loadedSeq int64
			if seq, err := vault.ReadConfigU64LE(s.cfg.Vault.Path, VaultChangeSeqKey); err == nil {
				loadedSeq = int64(seq)
			}
			p.SetReporter(nil, fmt.Sprintf("proxy-%d", id), s.version, fmt.Sprintf("gen-%d", id), loadedSeq, vaultReader.GetLoggedInAccountID())
		}
	}

	// Attach usage reporter if any upload destination is configured —
	// either the legacy single CollectorURL, or at least one non-empty
	// per-route entry under CollectorRoutes (added 2026-05-10 for
	// personal/team isolation). See roadmap update 20260510-personal-team-
	// 数据隔离与合并显示.md.
	var reporter *events.Reporter
	var canary *events.CanaryProbe
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
		reporter, err = events.NewReporter(events.ReporterConfig{
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
			if seq, err := vault.ReadConfigU64LE(s.cfg.Vault.Path, VaultChangeSeqKey); err == nil {
				loadedSeq = int64(seq)
			}
			p.SetReporter(reporter, fmt.Sprintf("proxy-%d", id), s.version, fmt.Sprintf("gen-%d", id), loadedSeq, vaultReader.GetLoggedInAccountID())
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
	}

	// Only hand the WAL to the generation when nobody else closes it. If a
	// reporter was attached it owns (and closes) the shared writer — passing
	// it here too would double-close on reload.
	var ownedWAL *events.WALWriter
	if reporter == nil {
		ownedWAL = sharedWAL
	}

	gen := &generation{
		id:            id,
		vaultPath:     s.cfg.Vault.Path,
		vault:         vaultReader,
		registry:      registry,
		providers:     providers,
		proxy:         p,
		collector:     collector,
		eventStore:    eventStore,
		reporter:      reporter,
		canary:        canary,
		filterHook:    filterHook,
		standaloneWAL: ownedWAL,
		seqAlloc:      seqAlloc,
		drained:       make(chan struct{}),
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
		"port drift exhausted: %s:%d..%d all occupied (last error: %v)",
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
