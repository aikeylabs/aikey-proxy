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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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
	reporter   *events.Reporter // usage reporter (nil when collector_url is not configured)

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
	// Close the reporter first so its upload loop flushes before the
	// collector and event store are torn down.
	if g.reporter != nil {
		_ = g.reporter.Close()
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

	active    atomic.Pointer[generation]
	reloadMu  sync.Mutex // serialise concurrent reload requests
	genID     atomic.Int64
	startedAt time.Time

	// ctx / cancel bound the lifetime of all detached upstream calls.
	// Cancelled in Shutdown() to stop any in-flight upstream requests.
	ctx    context.Context
	cancel context.CancelFunc
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
	go s.managedKeySyncLoop()
	return s, nil
}

// SetTransport sets the outbound RoundTripper used by all generations.
// Must be called before any requests are served (right after New).
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

	// Re-use the active generation's already-open vault reader instead of
	// calling vault.Open() (which re-runs the full Argon2id KDF on every tick).
	managedKeys, err := gen.vault.GetActiveManagedKeys()
	if err != nil || len(managedKeys) == 0 {
		// Update loaded seq even if no keys, so we don't retry on every tick.
		_ = vault.WriteConfigU64LE(s.cfg.Vault.Path, ProxyLoadedSeqKey, vaultSeq)
		return
	}

	managedRoutes := make(map[string]*vkeys.ResolvedRoute, len(managedKeys))
	for _, mk := range managedKeys {
		token := "aikey_vk_" + mk.VirtualKeyID
		managedRoutes[token] = &vkeys.ResolvedRoute{
			VirtualKeyID:       mk.VirtualKeyID,
			Provider:           mk.ProtocolType, // protocol type resolves to provider adapter (e.g. "openai_compatible" → openai)
			BaseURL:            mk.BaseURL,
			PlaintextKey:       mk.PlaintextKey,
			OrgID:              mk.OrgID,
			AccountID:          mk.OwnerAccountID,
			SeatID:             mk.SeatID,
			ProviderCode:       mk.ProviderCode,
			ProtocolType:       mk.ProtocolType,
			CredentialID:       mk.CredentialID,
			CredentialRevision: mk.CredentialRevision,
			VirtualKeyRevision: mk.VirtualKeyRevision,
		}
	}

	// Merge into the active generation's live registry — zero downtime, no reload.
	gen.registry.Merge(managedRoutes)

	// Record that we've caught up to this seq.
	if werr := vault.WriteConfigU64LE(s.cfg.Vault.Path, ProxyLoadedSeqKey, vaultSeq); werr != nil {
		slog.Warn("managed key sync: failed to write loaded_vault_change_seq", "error", werr)
	} else {
		slog.Info("managed key sync: merged active managed keys",
			"count", len(managedRoutes),
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
	go func() {
		old.drain(drainTimeoutStreaming, reloadID)
		old.close()
		slog.Info("reload: old generation closed",
			"reload_id", reloadID,
			"generation_id", old.id,
		)
	}()

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

	// Build virtual key registry from static YAML config.
	// Skip entries whose vault secret is missing (prevents proxy crash on misconfiguration).
	var activeKeys []config.VirtualKeyConfig
	for _, vk := range s.cfg.VirtualKeys {
		if _, err := vaultReader.GetSecret(vk.KeyAlias); err != nil {
			slog.Warn("virtual key skipped: API Key not found in vault — add it with 'aikey add'",
				"vk_id", vk.ID, "key_alias", vk.KeyAlias)
			continue
		}
		activeKeys = append(activeKeys, vk)
	}
	slog.Info("static virtual keys ready", "active", len(activeKeys), "total", len(s.cfg.VirtualKeys))

	registry := vkeys.NewRegistry()
	registry.Load(activeKeys)

	// Also load team-managed virtual keys from managed_virtual_keys_cache.
	// These are keys accepted via `aikey key accept` and activated via `aikey key use`.
	// The bearer token clients use is: "aikey_vk_" + virtual_key_id.
	if managedKeys, err := vaultReader.GetActiveManagedKeys(); err != nil {
		slog.Warn("could not load managed virtual keys", "error", err)
	} else if len(managedKeys) > 0 {
		managedRoutes := make(map[string]*vkeys.ResolvedRoute, len(managedKeys))
		for _, mk := range managedKeys {
			token := "aikey_vk_" + mk.VirtualKeyID
			managedRoutes[token] = &vkeys.ResolvedRoute{
				VirtualKeyID:       mk.VirtualKeyID,
				Provider:           mk.ProtocolType, // protocol type resolves to provider adapter (e.g. "openai_compatible" → openai)
				BaseURL:            mk.BaseURL,
				PlaintextKey:       mk.PlaintextKey,
				OrgID:              mk.OrgID,
				AccountID:          mk.OwnerAccountID,
				SeatID:             mk.SeatID,
				ProviderCode:       mk.ProviderCode,
				ProtocolType:       mk.ProtocolType,
				CredentialID:       mk.CredentialID,
				CredentialRevision: mk.CredentialRevision,
				VirtualKeyRevision: mk.VirtualKeyRevision,
			}
		}
		registry.Merge(managedRoutes)
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

	// Attach usage reporter if collector_url is configured.
	var reporter *events.Reporter
	if s.cfg.Events.CollectorURL != "" {
		var err error
		reporter, err = events.NewReporter(events.ReporterConfig{
			CollectorURL:    s.cfg.Events.CollectorURL,
			CollectorToken:  s.cfg.Events.CollectorToken,
			QueueCapacity:   s.cfg.Events.QueueCapacity,
			BatchSize:       s.cfg.Events.UploadBatchSize,
			UploadInterval:  s.cfg.Events.UploadInterval,
			WALDir:          s.cfg.Events.WALDir,
			ProxyInstanceID: fmt.Sprintf("proxy-%d", id),
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
		}
	}

	return &generation{
		id:         id,
		vaultPath:  s.cfg.Vault.Path,
		vault:      vaultReader,
		registry:   registry,
		providers:  providers,
		proxy:      p,
		collector:  collector,
		eventStore: eventStore,
		reporter:   reporter,
		drained:    make(chan struct{}),
	}, nil
}

// Listen creates and returns the TCP listener on the configured address.
// The caller should hold this listener for the lifetime of the process and
// pass it to http.Server.Serve so the port is never released during reloads.
func Listen(cfg *config.Config) (net.Listener, error) {
	ln, err := net.Listen("tcp", cfg.Listen.Addr())
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", cfg.Listen.Addr(), err)
	}
	return ln, nil
}
