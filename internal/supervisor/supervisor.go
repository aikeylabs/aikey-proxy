// Package supervisor implements a single-process dual-generation runtime for
// aikey-proxy.  It keeps the TCP listener open across vault reloads so that
// in-flight requests (including long-running SSE streams) are not interrupted.
//
// Architecture
//
//	Supervisor
//	  ├─ net.Listener  (held for the lifetime of the process)
//	  ├─ active  atomic.Pointer[generation]  (swapped on reload)
//	  └─ reload mutex  (serialises concurrent reload requests)
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
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
	case "kimi", "moonshot":
		return "https://api.kimi.com/coding"
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

	// standaloneWAL is only populated when this generation created the
	// local WAL writer AND no reporter consumed it — i.e. collector_url is
	// empty. When a reporter is present it owns the WAL and its Close()
	// closes it, so we leave standaloneWAL nil to avoid double-close. This
	// split is what keeps `generation.close()` from leaking file handles
	// on every reload in offline/standalone deployments.
	standaloneWAL *events.WALWriter

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
	reloadMu  sync.Mutex // serialise concurrent reload requests
	genID     atomic.Int64
	startedAt time.Time

	// ctx / cancel bound the lifetime of all detached upstream calls.
	// Cancelled in Shutdown() to stop any in-flight upstream requests.
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
		cfg:        cfg,
		configPath: configPath,
		password:   password,
		version:    version,
		startedAt:  time.Now(),
		ctx:        ctx,
		cancel:     cancel,
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
	return s, nil
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

// syncManagedKeys checks the vault change_seq and, if it has advanced since
// the active generation was built, merges current active managed keys into the
// live registry.
func (s *Supervisor) syncManagedKeys() {
	gen := s.active.Load()

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

	// 3. Personal key route tokens. Strict-form filter is centralised in
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

	// Atomic replace — deleted/revoked tokens disappear immediately.
	gen.registry.ReplaceAll(allRoutes)

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

// Handler returns an http.Handler that always delegates to the active generation.
// This is the function passed to the http.Server — it never changes across reloads.
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
	case "kimi", "moonshot":
		return "https://api.kimi.com/coding"
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
// It serialises concurrent calls: a second Reload waits for the first to finish.
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

// buildGeneration creates a fully-initialised generation ready to handle requests.
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
	loadVaultRoutesIntoRegistry(registry, vaultReader)

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

	// Create the local WAL writer unconditionally whenever WALDir is set.
	// This is the canonical event log used by `aikey statusline` / `aikey watch`,
	// and it must exist even in standalone (no collector_url) deployments —
	// the reporter is only one of several consumers.  When the reporter is
	// also created below we hand it this shared instance so there is only a
	// single writer touching the directory.
	var sharedWAL *events.WALWriter
	if s.cfg.Events.WALDir != "" {
		if w, werr := events.NewWALWriter(s.cfg.Events.WALDir); werr != nil {
			slog.Warn("local wal init failed, offline usage log disabled", "error", werr)
		} else {
			sharedWAL = w
			// Always attach to proxy.  When reporter is nil this is the only
			// sink; when reporter is non-nil the proxy skips direct append
			// (reporter.Report handles it via the shared instance).
			p.SetWAL(sharedWAL)
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

	// Attach usage reporter if collector_url is configured.
	var reporter *events.Reporter
	var canary *events.CanaryProbe
	if s.cfg.Events.CollectorURL != "" {
		var err error
		reporter, err = events.NewReporter(events.ReporterConfig{
			CollectorURL:    s.cfg.Events.CollectorURL,
			CollectorToken:  s.cfg.Events.CollectorToken,
			QueueCapacity:   s.cfg.Events.QueueCapacity,
			BatchSize:       s.cfg.Events.UploadBatchSize,
			UploadInterval:  s.cfg.Events.UploadInterval,
			WALDir:          s.cfg.Events.WALDir,
			SharedWAL:       sharedWAL,
			ProxyInstanceID: fmt.Sprintf("proxy-%d", id),
			ConfigHash:      s.cfg.PipelineConfigHash(),
			DBPath:          s.cfg.Events.DBPath,
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

	return &generation{
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
		standaloneWAL: ownedWAL,
		drained:       make(chan struct{}),
	}, nil
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
// EADDRINUSE). driftMax == 0 is honoured by config.applyDefaults() — yaml
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
