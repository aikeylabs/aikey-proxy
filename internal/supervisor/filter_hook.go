// filter_hook.go — P4 Phase 2: construct + spawn the compliance filter hook
// and wire it into the per-generation proxy.
//
// This is the supervisor half of the P4 filter dispatcher. Phase 1 added the
// in-request dispatch (proxy/filter_dispatch.go); this decides, at generation
// build time, WHETHER a filter runs and spawns the child if so.
//
// Why here (not in proxy.New): the hook is a long-running child process with a
// lifecycle tied to the generation (spawned on build, Shutdown on reload-drain).
// The supervisor already owns generation lifecycle (vault, reporter, collector
// all close in generation.close()), so the filter child belongs in the same
// place — one teardown path, no leaked child on reload.
//
// Three outcomes (see installFilterHook):
//  1. No filter declared    → no hook, normal serving (zero cost).
//  2. Binary resolvable      → spawn. Success → real dispatch.
//                              Spawn failure → fail-loud 501 (anti-example F).
//  3. Declared but no binary → fail-loud 501 (can't honor declaration).
package supervisor

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// Filter hook wiring is driven by env so the live closed loop can run before
// `aikey app install` populates a binary path in vault app_records (E2, not yet
// wired). When E2 lands, the binary path moves into the app record and the
// env override stays as a dev/test escape hatch.
const (
	// filterBinaryEnv: absolute path to the filter app child binary
	// (ai-compliance-detector). Set → supervisor spawns it as the proxy's
	// filter hook. Unset → fall back to vault app_records declaration.
	filterBinaryEnv = "AIKEY_PROXY_FILTER_BINARY"
	// filterArgsEnv: optional space-separated extra args for the child
	// (e.g. "--rules /path/to/rules.yaml"). Empty → child uses its embedded
	// baseline ruleset, which is the production default.
	filterArgsEnv = "AIKEY_PROXY_FILTER_ARGS"
	// filterTimeoutMsEnv: per-Detect deadline override in ms. The apphook
	// default is 1ms, which is too tight for real NER+AC on a full prompt —
	// it would constantly time out → degrade → fail-open (nothing masked).
	// We default to filterDefaultTimeout so detection actually completes.
	filterTimeoutMsEnv = "AIKEY_PROXY_FILTER_TIMEOUT_MS"
)

// filterDefaultTimeout is the per-Detect deadline when no override is set.
// Chosen to comfortably cover Engine.Detect (AC scan + CRF NER + planner) on a
// realistic prompt while still bounding the hot path. Fail-open on overrun
// (§6 #11) means a too-low value silently disables masking, so we err generous.
const filterDefaultTimeout = 80 * time.Millisecond

// installFilterHook decides whether this generation runs a compliance/DLP
// filter hook, spawns it if so, and wires it into p.
//
// Returns the spawned child (nil if none) so the caller stores it in the
// generation and calls Shutdown on reload-drain. A nil return means "no live
// child to tear down" — either nothing was declared, or spawn failed and the
// proxy is in fail-loud 501 mode instead.
func (s *Supervisor) installFilterHook(p *proxy.Proxy, vaultReader *vault.Reader) *apphook.ChildHook {
	binPath, binArgs, slug, declaredButMissing := s.resolveFilterBinary(vaultReader)
	if binPath == "" {
		if declaredButMissing {
			// Vault declares a filter app but its installed binary can't be
			// resolved. Fail loud — do NOT pass traffic through unfiltered
			// (anti-example F). Re-evaluated each Reload, so it self-heals once
			// `aikey app install` lays the binary down.
			slog.Warn("supervisor: vault declares a filter app but its binary was not found "+
				"(expected <apps_dir>/<slug>/bin/<slug>, or set "+filterBinaryEnv+"). "+
				"Data-plane returns 501 until resolved. SPEC §1.5.7 anti-example F.",
				"event.name", "proxy.filter_stub_active")
			p.SetFilterStub501Active(true)
		}
		return nil // nothing declared (normal serving), or declared-but-missing (501 set)
	}

	// Pass the per-app record-allow flag to the detector as env so it can drop
	// clean "allow" scans at source. Default off; on a flag change the vault
	// change_seq bump triggers a proxy reload → this hook re-installs → the
	// child re-spawns with the new value. The dev-override path has no slug
	// (slug==""), so it just gets the default-off env.
	recordAllow := false
	if slug != "" {
		if ra, err := vaultReader.GetFilterRecordAllow(slug); err != nil {
			slog.Warn("supervisor: read filter_record_allow failed; defaulting off",
				"event.name", "proxy.filter_record_allow_read_failed", "slug", slug, "error", err)
		} else {
			recordAllow = ra
		}
	}
	recordAllowEnv := "AIKEY_COMPLIANCE_RECORD_ALLOW=0"
	if recordAllow {
		recordAllowEnv = "AIKEY_COMPLIANCE_RECORD_ALLOW=1"
	}

	cfg := apphook.ChildHookConfig{
		Name:       "ai-compliance-detector",
		BinaryPath: binPath,
		BinaryArgs: binArgs,
		Timeout:    filterTimeout(),
		ExtraEnv:   []string{recordAllowEnv},
	}
	hook := apphook.NewChildHook(cfg)
	if err := hook.Start(s.ctx); err != nil {
		// We have a binary but can't run it (missing/perm, protocol-version
		// drift, engine init crash). Fail loud — refuse traffic rather than
		// silently forwarding unfiltered.
		slog.Error("supervisor: filter hook spawn failed; enabling fail-loud 501",
			"event.name", "proxy.filter_spawn_failed",
			"binary", binPath, "error", err)
		p.SetFilterStub501Active(true)
		_ = hook.Shutdown(context.Background()) // best-effort; never started → no-op
		return nil
	}

	p.SetFilterHook(hook)
	slog.Info("supervisor: compliance filter hook active",
		"event.name", "proxy.filter_hook_active",
		"binary", binPath,
		"timeout_ms", filterTimeout().Milliseconds())
	return hook
}

// resolveFilterBinary picks the filter child binary to spawn:
//   - the AIKEY_PROXY_FILTER_BINARY env override (dev), if set; else
//   - the installed binary of a vault-declared filter app, resolved by
//     convention (<apps_dir>/<slug>/bin/<slug>) — the path `aikey app install`
//     lays the detector down at.
//
// Returns ("", nil, false) when nothing is declared (normal serving), and
// ("", nil, true) when a filter app IS declared but no binary was found
// (caller fails loud rather than serving unfiltered).
func (s *Supervisor) resolveFilterBinary(vaultReader *vault.Reader) (binPath string, args []string, slug string, declaredButMissing bool) {
	if env := strings.TrimSpace(os.Getenv(filterBinaryEnv)); env != "" {
		// Dev override: no slug → caller can't read per-app vault config (gets
		// the record-allow default-off env).
		return env, strings.Fields(os.Getenv(filterArgsEnv)), "", false
	}
	slugs, err := vaultReader.GetFilterAppSlugs()
	if err != nil {
		slog.Warn("supervisor: filter_stages check failed; treating as inactive",
			"event.name", "proxy.filter_stub_check_failed", "error", err)
		return "", nil, "", false
	}
	if len(slugs) == 0 {
		return "", nil, "", false
	}
	if bin, sl := resolveAppBinary(s.appsDir(), slugs); bin != "" {
		return bin, nil, sl, false
	}
	return "", nil, "", true
}

// appsDir is where `aikey app install` lays out app trees, derived from the
// vault path (<home>/.aikey/data/vault.db → <home>/.aikey/apps).
func (s *Supervisor) appsDir() string {
	return filepath.Join(filepath.Dir(filepath.Dir(s.cfg.Vault.Path)), "apps")
}

// resolveAppBinary returns the first existing <appsDir>/<slug>/bin/<slug> file
// and its slug, or ("","") if none. Pure (filesystem only) — unit-testable with
// a temp dir. The slug lets the caller read per-app vault config (e.g.
// filter_record_allow) for the binary it actually resolved.
func resolveAppBinary(appsDir string, slugs []string) (bin string, slug string) {
	for _, s := range slugs {
		b := filepath.Join(appsDir, s, "bin", s)
		if fi, err := os.Stat(b); err == nil && !fi.IsDir() {
			return b, s
		}
	}
	return "", ""
}

// filterTimeout resolves the per-Detect deadline: env override (ms) if a valid
// positive integer, else filterDefaultTimeout.
func filterTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv(filterTimeoutMsEnv))
	if raw == "" {
		return filterDefaultTimeout
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		slog.Warn("supervisor: invalid "+filterTimeoutMsEnv+"; using default",
			"event.name", "proxy.filter_timeout_invalid", "value", raw)
		return filterDefaultTimeout
	}
	return time.Duration(ms) * time.Millisecond
}
