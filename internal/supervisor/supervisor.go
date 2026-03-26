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
	"sync"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
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
func (g *generation) drain(timeout time.Duration) {
	g.draining.Store(true)
	if g.inflight.Load() == 0 {
		select {
		case <-g.drained:
		default:
			close(g.drained)
		}
		return
	}
	select {
	case <-g.drained:
		slog.Info("generation drained", "id", g.id)
	case <-time.After(timeout):
		slog.Warn("generation drain timed out, forcing close", "id", g.id, "inflight", g.inflight.Load())
	}
}

// Supervisor manages the proxy lifecycle and exposes the data-plane handler.
type Supervisor struct {
	cfg      *config.Config
	password string

	active   atomic.Pointer[generation]
	reloadMu sync.Mutex // serialise concurrent reload requests
	genID    atomic.Int64
}

// New creates a Supervisor and starts the initial generation.
func New(cfg *config.Config, password string) (*Supervisor, error) {
	s := &Supervisor{cfg: cfg, password: password}
	gen, err := s.buildGeneration()
	if err != nil {
		return nil, fmt.Errorf("initial generation failed: %w", err)
	}
	s.active.Store(gen)
	slog.Info("supervisor started", "gen", gen.id)
	return s, nil
}

// Handler returns an http.Handler that always delegates to the active generation.
// This is the function passed to the http.Server — it never changes across reloads.
func (s *Supervisor) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.active.Load().ServeHTTP(w, r)
	})
}

// AdminHandler returns the current generation's event store (for admin metrics).
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

// Reload builds a new generation, swaps it as active if the readiness gate
// passes, drains the old generation, and records the loaded vault change_seq.
// It serialises concurrent calls: a second Reload waits for the first to finish.
func (s *Supervisor) Reload(ctx context.Context) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	slog.Info("reload: building new generation")
	newGen, err := s.buildGeneration()
	if err != nil {
		return fmt.Errorf("reload: build generation failed: %w", err)
	}

	old := s.active.Load()

	// Swap to new generation — new requests go to newGen from this point.
	s.active.Store(newGen)
	slog.Info("reload: new generation active", "gen", newGen.id)

	// Record which vault snapshot the new generation loaded.
	if vaultSeq, err := vault.ReadConfigU64LE(s.cfg.Vault.Path, VaultChangeSeqKey); err == nil {
		if werr := vault.WriteConfigU64LE(s.cfg.Vault.Path, ProxyLoadedSeqKey, vaultSeq); werr != nil {
			slog.Warn("reload: failed to write loaded_vault_change_seq", "error", werr)
		} else {
			slog.Info("reload: wrote loaded_vault_change_seq", "seq", vaultSeq)
		}
	}

	// Drain the old generation asynchronously so the reload call returns promptly.
	go func() {
		slog.Info("reload: draining old generation", "gen", old.id)
		old.drain(drainTimeoutStreaming)
		old.close()
		slog.Info("reload: old generation closed", "gen", old.id)
	}()

	return nil
}

// Shutdown drains the active generation and closes all resources.
func (s *Supervisor) Shutdown(timeout time.Duration) {
	gen := s.active.Load()
	slog.Info("supervisor shutting down", "gen", gen.id)
	gen.drain(timeout)
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

	// Build virtual key registry, skip keys whose vault secret is missing.
	var activeKeys []config.VirtualKeyConfig
	for _, vk := range s.cfg.VirtualKeys {
		if _, err := vaultReader.GetSecret(vk.KeyAlias); err != nil {
			slog.Warn("virtual key skipped: secret not found in vault — add it with 'aikey secret set'",
				"vk_id", vk.ID, "key_alias", vk.KeyAlias)
			continue
		}
		activeKeys = append(activeKeys, vk)
	}
	slog.Info("virtual keys ready", "active", len(activeKeys), "total", len(s.cfg.VirtualKeys))

	registry := vkeys.NewRegistry()
	registry.Load(activeKeys)

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

	// Build the proxy handler.
	p := proxy.New(vaultReader, registry, providers, collector)

	return &generation{
		id:         id,
		vaultPath:  s.cfg.Vault.Path,
		vault:      vaultReader,
		registry:   registry,
		providers:  providers,
		proxy:      p,
		collector:  collector,
		eventStore: eventStore,
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
