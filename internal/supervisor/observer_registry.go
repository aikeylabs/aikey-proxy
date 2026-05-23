package supervisor

import (
	"log/slog"

	"github.com/AiKeyLabs/aikey-proxy/internal/observer/ndjson_fanout"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// buildObserverRegistry constructs the per-generation observer.Registry
// for a Proxy gen. Returns nil if no observers are registered in the
// process-global registration sink (i.e., no first-party observer
// plugin was blank-imported in main.go) — Proxy.SetObserverRegistry(nil)
// makes Notify* hooks no-op.
//
// Why per-generation: aligns with the gen-scoped lifecycle of Proxy
// instances. Each reload (vault change, config reload) builds a fresh
// Proxy + fresh observer registry; the observer descriptors themselves
// are process-global (init-time registrations) but the live observer
// instances + their per-request state are gen-scoped, so a reload
// cleanly cuts over to fresh observer state without bleeding across
// generations.
//
// `cfg` is supervisor.Config.Observers — a map keyed by observer.Name
// whose values are forwarded as-is to each observer's Build callback.
//
// Enable-check: uses observer.DefaultVaultEnableCheck, which returns
// true iff the observer's owner app is "live" in this user's vault
// (app_records row present + at least one active app_keys row). When
// degrade-detector is not installed, the rhythm observer is skipped at
// Build time and Notify* hooks see an empty observer set.
func buildObserverRegistry(
	v *vault.Reader,
	cfg map[string]map[string]any,
	logger *slog.Logger,
) *observer.Registry {
	if logger == nil {
		logger = slog.Default()
	}
	if len(observer.RegisteredObservers()) == 0 {
		logger.Info("supervisor: no observer descriptors registered, skipping observer registry construction",
			"event.name", "proxy.observer.no_registrations")
		return nil
	}
	// Inject the vault into the ndjson-fanout observer BEFORE BuildObservers
	// runs. The framework's Build callback receives only `cfg map[string]any`
	// (no vault) so observers needing vault access read it from a package-
	// local setter; supervisor is the natural wiring point because it owns
	// the *vault.Reader lifecycle (see buildGeneration in supervisor.go).
	ndjson_fanout.SetVaultReader(ndjson_fanout.NewVaultBridge(v))

	reg := observer.NewRegistry(logger)
	adapter := newSupervisorVaultObserverAdapter(v)
	// Slugs whose observers are always enabled regardless of vault state
	// (proxy-bundled infrastructure, not user-installed apps). Currently:
	//   aikey-proxy-core  — owns the ndjson-fanout observer (SPEC §1.4)
	//
	// DefaultVaultEnableCheck would reject these (no app_records row to
	// confirm "live") so we short-circuit before reaching it. Adding new
	// always-on slugs here is intentional friction: every entry implies
	// extra proxy memory + IO; PR review should confirm.
	alwaysOn := map[string]bool{
		"aikey-proxy-core": true,
	}
	enableCheck := func(slug string) bool {
		if alwaysOn[slug] {
			return true
		}
		return observer.DefaultVaultEnableCheck(slug, adapter, logger)
	}
	reg.BuildObservers(enableCheck, cfg)
	if reg.Active() == 0 {
		logger.Info("supervisor: observer registry built, but zero active observers (all enable checks returned false)",
			"event.name", "proxy.observer.zero_active")
	}
	return reg
}

// supervisorVaultObserverAdapter mirrors internal/proxy.vaultObserverAdapter
// — kept here (rather than importing from internal/proxy) so this package
// doesn't form a dep cycle: supervisor → proxy. The adapter is the same
// 25 lines; duplication is acceptable because the observer.VaultGetter
// interface is tiny and stable.
type supervisorVaultObserverAdapter struct {
	r *vault.Reader
}

func newSupervisorVaultObserverAdapter(r *vault.Reader) observer.VaultGetter {
	if r == nil {
		return nil
	}
	return &supervisorVaultObserverAdapter{r: r}
}

func (a *supervisorVaultObserverAdapter) GetAppRecord(slug string) (interface{ GetSlug() string }, error) {
	rec, err := a.r.GetAppRecord(slug)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		// Explicit interface-nil return; see the proxy-side adapter's
		// comment for the typed-nil-vs-interface-nil rationale.
		return nil, nil
	}
	return rec, nil
}

func (a *supervisorVaultObserverAdapter) GetActiveAppKeysForSlug(slug string) (int, error) {
	return a.r.GetActiveAppKeysForSlug(slug)
}
