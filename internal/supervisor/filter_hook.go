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
	"encoding/json"
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
func (s *Supervisor) installFilterHook(p *proxy.Proxy, vaultReader *vault.Reader) apphook.FilterTarget {
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

	// Explicitly enable the detector's Personal/Trial local-intake path. Why an
	// explicit flag instead of letting the detector self-decide: the detector
	// self-discovers the local-server URL from the CLI yaml, which exists on any
	// dev machine — so a test/bench that spawns the detector binary directly
	// (e.g. TestChildHookFullStackLatency, N=1000 fixture iterations) would
	// otherwise upload its fixtures into the live audit DB. Only the real
	// supervisor sets this, so tests stay isolated. Harmless on Production: the
	// detector checks AIKEY_CONTROL_MASTER_URL first and takes the master path
	// before ever reaching the local-intake gate.
	const localIntakeEnv = "AIKEY_COMPLIANCE_LOCAL_INTAKE=1"

	// Pass the team control-panel URL so the detector's pack puller pulls
	// compliance packs from that backend (public /v1/packs/changed, no token).
	// Injected as AIKEY_PACK_MASTER_URL — NOT AIKEY_CONTROL_MASTER_URL — so it
	// drives ONLY pack pulling, never the detector's event-intake routing (which
	// must stay LOCAL self-view on Personal; setting the control-master URL there
	// would switch intake to the master path and, with no app token, disable it).
	// The URL's single source is config.json controlPanelUrl (set by
	// `aikey login --control-url`); the proxy is the conduit, the detector keeps
	// NO copy. Empty (no team configured) → puller stays offline.
	extraEnv := []string{recordAllowEnv, localIntakeEnv}
	// Resolve the pack-pull backend + tenant for the detector. Personal/Trial read
	// the team URL from the CLI's config.json (no tenant scoping — one user, one
	// view). A CLUSTER node has no CLI config.json; its control URL + org come from
	// the shared cluster-node.env (the same AIKEY_HUB_* the daemon uses — proxy and
	// daemon both EnvironmentFile= it). Single-tenant per node (gap2 decision), so
	// AIKEY_TENANT_ID is a single value scoping the pull to THIS org's packs.
	// Reusing the existing detector pack-puller (GET /v1/packs/changed, which already
	// ships phrases + does atomic ruleset swap) means org-custom phrases reach the
	// node with no new endpoint/protocol — only these two env vars.
	masterURL := readControlPanelURL()
	tenantID := ""
	if s.cfg != nil && s.cfg.Cluster.Enabled {
		if u := os.Getenv("AIKEY_HUB_CONTROL_URL"); u != "" {
			masterURL = strings.TrimRight(u, "/")
		}
		tenantID = os.Getenv("AIKEY_HUB_ORG_ID")
	}
	if masterURL != "" {
		// Bound to a backend → pull packs from it, and poll every 60s so a newly
		// published pack appears within ~1 minute (the detector's default is 1h,
		// too slow for "add pack → see it"). Incremental cursor-based pulls are
		// cheap. Offline (no backend) → neither var is set, puller stays off.
		extraEnv = append(extraEnv,
			"AIKEY_PACK_MASTER_URL="+masterURL,
			"AIKEY_PACK_POLL_INTERVAL=60s",
		)
		if tenantID != "" {
			extraEnv = append(extraEnv, "AIKEY_TENANT_ID="+tenantID)
		}
	}

	cfg := apphook.ChildHookConfig{
		Name:       "ai-compliance-detector",
		BinaryPath: binPath,
		BinaryArgs: binArgs,
		Timeout:    filterTimeout(),
		ExtraEnv:   extraEnv,
	}
	// Pool of M independent detector processes (双进程+A: cross-process isolation
	// on top of each process's internal worker pool). M from AIKEY_PROXY_FILTER_WORKERS
	// (default 1 = single process / Personal/Trial). Each child inherits the proxy
	// env, including AIKEY_COMPLIANCE_WORKERS (K, the detector's internal pool size).
	m := filterWorkerCount()
	workers := make([]*apphook.ChildHook, m)
	for i := range workers {
		workers[i] = apphook.NewChildHook(cfg)
	}
	pool := apphook.NewFilterPool("ai-compliance-detector", workers)
	if err := pool.Start(s.ctx); err != nil {
		// NONE of the M processes could run (missing/perm, protocol-version drift,
		// engine init crash). Fail loud — refuse traffic rather than forwarding
		// unfiltered. (If only some failed, the pool stays up and they self-heal.)
		slog.Error("supervisor: filter hook spawn failed; enabling fail-loud 501",
			"event.name", "proxy.filter_spawn_failed",
			"binary", binPath, "workers", m, "error", err)
		p.SetFilterStub501Active(true)
		_ = pool.Shutdown(context.Background()) // best-effort; never started → no-op
		return nil
	}

	p.SetFilterHook(pool)
	slog.Info("supervisor: compliance filter hook active",
		"event.name", "proxy.filter_hook_active",
		"binary", binPath,
		"workers", m,
		"timeout_ms", filterTimeout().Milliseconds())
	return pool
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

// filterWorkersEnv sets M, the number of independent detector PROCESSES the pool
// spawns. Default 1 (Personal/Trial — behaviour unchanged). Production sets 2 for
// cross-process fault isolation. K (goroutines per process) is a separate knob,
// AIKEY_COMPLIANCE_WORKERS, read by the detector itself (inherited from the proxy
// env).
const filterWorkersEnv = "AIKEY_PROXY_FILTER_WORKERS"

// filterWorkerCount resolves M from filterWorkersEnv (default 1, clamped ≥1).
func filterWorkerCount() int {
	raw := strings.TrimSpace(os.Getenv(filterWorkersEnv))
	if raw == "" {
		return 1
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		slog.Warn("supervisor: invalid "+filterWorkersEnv+"; using 1",
			"event.name", "proxy.filter_workers_invalid", "value", raw)
		return 1
	}
	return n
}

// readControlPanelURL reads the team control-panel URL from the CLI's single
// source: ~/.aikey/config/config.json `controlPanelUrl` (written by
// `aikey login --control-url`). The proxy passes it to the detector as
// AIKEY_CONTROL_MASTER_URL so the pack puller pulls compliance packs from the
// team backend. The detector keeps NO copy of this URL — the proxy is the sole
// conduit (single source). Returns "" on any read/parse miss (no team / fresh
// install) → puller stays offline, no error.
func readControlPanelURL() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, ".aikey", "config", "config.json"))
	if err != nil {
		return ""
	}
	var cfg struct {
		ControlPanelURL string `json:"controlPanelUrl"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return ""
	}
	return strings.TrimRight(cfg.ControlPanelURL, "/")
}
