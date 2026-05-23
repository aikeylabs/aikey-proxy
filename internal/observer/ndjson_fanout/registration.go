package ndjson_fanout

// registration.go — init() time observer registration + vault bridge.
//
// Wiring:
//
//	main.go imports this package via blank-import → init() registers the
//	  observer descriptor (no vault access yet — happens at Build time)
//	main.go calls SetVaultReader(NewVaultBridge(vaultReader)) right after
//	  opening the vault, BEFORE supervisor.buildObserverRegistry runs
//	supervisor.buildObserverRegistry calls each Observer.Build callback
//	  → our Build closure reads the registered VaultReader and constructs
//	  the fanout observer
//
// Why a package-local SetVaultReader instead of a generic process-global
// in pkg/observer: the framework currently only exposes a slug-based
// enableCheck to Build callbacks (no full vault access). Adding a global
// at the framework level would force every other observer to think about
// it. A package-private setter keeps the coupling contained.

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// observerName is the unique key under which this observer registers.
// Used for log attribution + observer.Registry uniqueness check.
const observerName = "ndjson-fanout"

// ownerSlug is the synthetic first-party slug we register under. Lives
// in observer.FirstPartyAllowlist (see pkg/observer/registry.go). The
// supervisor's enable check special-cases this slug to always-on, since
// no actual app_records row exists for it.
const ownerSlug = "aikey-proxy-core"

// registeredVault is the VaultReader the proxy startup wiring injects
// before BuildObservers. nil here causes Build to fail loudly — better
// than starting a dead observer.
var (
	registeredVaultMu sync.RWMutex
	registeredVault   VaultReader
)

// SetVaultReader is the wiring entry point — main.go calls this after
// opening the vault and before supervisor's BuildObservers runs. nil is
// rejected at Build time, not here, so unit tests can clear the value
// safely between scenarios.
func SetVaultReader(v VaultReader) {
	registeredVaultMu.Lock()
	defer registeredVaultMu.Unlock()
	registeredVault = v
}

// currentVaultReader is the read-side accessor; only Build() and the
// test harness use it.
func currentVaultReader() VaultReader {
	registeredVaultMu.RLock()
	defer registeredVaultMu.RUnlock()
	return registeredVault
}

func init() {
	observer.RegisterObserver(observer.Observer{
		Name:         observerName,
		OwnerAppSlug: ownerSlug,
		// SPEC §1.4: this observer is the generic file-fanout for every
		// observable pipeline. Declaring all three streams here is the
		// SPEC-aligned scope — internal routing (which subscriber gets
		// which file) is then handled by our own per-stream routing
		// table built from vault data.
		Streams: observer.AllStreams(),
		Build:   build,
	})
}

// build is the Observer.Build callback. Called once at proxy startup by
// supervisor.buildObserverRegistry. cfg comes from the proxy yaml
// `observers.ndjson-fanout` block (today: just `base_dir` override).
//
// Returns an error if vault isn't wired or baseDir resolution fails;
// the observer framework treats the error as "skip this observer" — the
// proxy continues to start without ndjson-fanout but logs WARN.
func build(cfg map[string]any) (observer.StreamingObserver, error) {
	v := currentVaultReader()
	if v == nil {
		return nil, fmt.Errorf(
			"ndjson_fanout: vault reader not set; main.go must call " +
				"ndjson_fanout.SetVaultReader before observer registry build")
	}
	baseDir, err := resolveBaseDir(cfg)
	if err != nil {
		return nil, fmt.Errorf("ndjson_fanout: resolve base_dir: %w", err)
	}
	return New(slog.Default().With("component", "ndjson-fanout"), baseDir, v)
}

// resolveBaseDir picks the on-disk root for per-subscriber files.
// Priority: yaml `base_dir` (test override / advanced users) →
// `~/.aikey/data/observers/` (SPEC §1.4.4 default).
func resolveBaseDir(cfg map[string]any) (string, error) {
	if cfg != nil {
		if v, ok := cfg["base_dir"].(string); ok && v != "" {
			return v, nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home: %w", err)
	}
	return filepath.Join(home, ".aikey", "data", "observers"), nil
}

// -----------------------------------------------------------------------------
// Vault bridge — adapts *vault.Reader to this package's VaultReader interface.
//
// Lives here (rather than in supervisor/) so the ndjson_fanout package is
// self-contained: callers wire it as `SetVaultReader(NewVaultBridge(r))`
// without needing to know the adapter's shape.
// -----------------------------------------------------------------------------

// NewVaultBridge returns a VaultReader that delegates to *vault.Reader.
// Used by main.go at startup time. nil-safe: returns nil → Build will
// fail loudly per the contract above.
func NewVaultBridge(r *vault.Reader) VaultReader {
	if r == nil {
		return nil
	}
	return &vaultBridge{r: r}
}

type vaultBridge struct {
	r *vault.Reader
}

func (b *vaultBridge) ListObserveSubscriptions() ([]observerSubscription, error) {
	raw, err := b.r.ListObserveSubscriptions()
	if err != nil {
		return nil, err
	}
	out := make([]observerSubscription, 0, len(raw))
	for _, s := range raw {
		out = append(out, observerSubscription{
			Slug:         s.Slug,
			Stream:       s.Stream,
			PayloadLevel: s.PayloadLevel,
		})
	}
	return out, nil
}
