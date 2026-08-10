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
//     Spawn failure → fail-loud 501 (anti-example F).
//  3. Declared but no binary → fail-loud 501 (can't honor declaration).
package supervisor

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
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
	// filterReadyTimeoutMsEnv: how long to wait for the detector child to signal
	// ready at spawn (NOT the per-request deadline above). Override in ms.
	filterReadyTimeoutMsEnv = "AIKEY_PROXY_FILTER_READY_TIMEOUT_MS"
)

// ─────────────────────────────────────────────────────────────────────────────
// Per-Detect deadline — MUST stay above the detector's own lane budget
// ─────────────────────────────────────────────────────────────────────────────
//
// WHAT this deadline is for: it is a DEGRADE THRESHOLD, not latency control
// (requirements 2026-06-13 form2-compliance-detector-worker-sizing: "per-Detect
// 超时…是 degrade 阈值，不缩短延迟"). Overrun does not make the request faster —
// it makes it UNSCANNED: the hook returns Degraded → fail-open → nothing is
// masked, and 'degraded' verdicts are deliberately not cached, so the same piece
// is rescanned and re-times-out every single turn.
//
// 🔴 WHY IT MOVED FROM 80ms (2026-08-10): 80ms was set on 2026-06-01 in the
// first compliance commit and never revisited. On 2026-08-08 the detector gained
// ENGINE-LEVEL tiered lane deadlines (用户拍板, the single source of truth for
// all four lanes: inputs ≤16KB → 100ms, larger → 1s). That made the proxy's
// budget STRICTER than the engine's own — the proxy gave up at 80ms on work the
// engine was still allowed to spend 100ms on, so the tier the user actually
// decided could never be reached and its only observable effect was the
// degrade/fail-open path above. A budget that expires before the thing it is
// budgeting for is not a safety margin; it is a silent masking-off switch.
//
// THE RULE, now fenced (TestFilterTimeout_ExceedsDetectorLaneBudget): the proxy
// must always time out AFTER the detector, so the detector's own deadline is the
// one that fires and the proxy's is reserved for the case the detector cannot
// answer at all (hung child, desynced pipe). Both properties are kept: the value
// is finite, so a wedged detector still degrades within ~1 request's latency.
//
// WHY the small tier is the only one that counts: the proxy never hands the
// detector more than pipeInputCap (16KB) per piece, and the tier is chosen on
// the pre-truncation input size — so from this process the ≥16KB / 1s tier is
// structurally unreachable. Budgeting for 1s would only slow down the hung-child
// case for no coverage gain.
const (
	// detectorLaneDeadlineSmall MIRRORS ai-compliance-detector's laneDeadlineSmall
	// (internal/compliance/engine.go). It cannot be imported — separate module,
	// and the detector is a spawned child, not a library — so the mirror is
	// verified against the detector's source by
	// TestFilterTimeout_MirrorsDetectorLaneDeadline whenever both repos are in
	// the same tree (always, in this monorepo / in CI).
	detectorLaneDeadlineSmall = 100 * time.Millisecond
	// detectorIPCMargin covers what the lane deadline does NOT: the framed pipe
	// round-trip, the child's req-id demux, action policy + planner after the
	// lanes finish, and goroutine scheduling on a loaded 2-core box. Generous on
	// purpose — the cost of being too small is "masking silently off", the cost of
	// being too large is a few tens of ms on the rare pathological request.
	detectorIPCMargin = 50 * time.Millisecond
	// filterDefaultTimeout is the per-Detect deadline when no override is set.
	filterDefaultTimeout = detectorLaneDeadlineSmall + detectorIPCMargin
)

// filterDefaultReadyTimeout is how long the supervisor waits for the detector
// child to signal ready at spawn. The apphook default is 5s, but the detector
// cold-loads CRF models + AC lexicons (~3s idle on a 2-core box) and that
// stretches past 5s under the load of a concurrent deploy/restart — the spawn
// then misses the deadline and latches fail-loud 501, even though the child is
// fine (found 2026-06-13: lobster de-1 flapped 200/501 across restarts, the
// detector ready'd in 2.9s standalone). 30s gives comfortable headroom on a
// busy small box while still bounding a genuinely-stuck child. A real engine
// init crash still fails after this and correctly latches 501 (fail-loud).
const filterDefaultReadyTimeout = 30 * time.Second

// installFilterHook decides whether this generation runs a compliance/DLP
// filter hook, spawns it if so, and wires it into p.
//
// Returns the spawned child (nil if none) so the caller stores it in the
// generation and calls Shutdown on reload-drain. A nil return means "no live
// child to tear down" — either nothing was declared, or spawn failed and the
// proxy is in fail-loud 501 mode instead.
func (s *Supervisor) installFilterHook(p *proxy.Proxy, vaultReader *vault.Reader) apphook.FilterTarget {
	// Operator kill-switch (用户 2026-06-17):AIKEY_DE_COMPLIANCE=off explicitly turns
	// compliance OFF — no filter hook, and NO fail-loud 501 even on a mandate org. Lets the
	// de operator toggle compliance by editing one line in the de-proxy.env config + restart,
	// without uninstalling the detector. Default (unset / "on") → normal wiring below.
	if complianceDisabledByOperator() {
		slog.Info("supervisor: compliance disabled by operator (AIKEY_DE_COMPLIANCE=off) — filter hook NOT installed, traffic forwarded unfiltered",
			"event.name", "proxy.filter.disabled_by_operator")
		p.SetFilterStub501Active(false) // ensure we are NOT in fail-loud mode
		return nil
	}
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
		Name:         "ai-compliance-detector",
		BinaryPath:   binPath,
		BinaryArgs:   binArgs,
		Timeout:      filterTimeout(),
		ReadyTimeout: filterReadyTimeout(),
		ExtraEnv:     extraEnv,
	}
	// Pool of M independent detector processes (双进程+A: cross-process isolation
	// on top of each process's internal worker pool). M from AIKEY_PROXY_FILTER_WORKERS
	// (default 1 = single process / Personal/Trial). Each child inherits the proxy
	// env, including AIKEY_COMPLIANCE_WORKERS (K, the detector's internal pool size).
	m := filterWorkerCount()
	workers := make([]*apphook.ChildHook, m)
	for i := range workers {
		workers[i] = apphook.NewChildHook(&cfg)
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
	// Incremental scan (latest user turn only) — opt-in via env, set by the
	// form-② lobster install. Default off = full scan (unchanged for fleet/other
	// editions). See Proxy.filterIncremental.
	incremental := filterIncrementalScan()
	p.SetFilterIncrementalScan(incremental)
	// content-hash 缓存(设计 20260616-…-内容哈希缓存 §4):opt-in via env,默认 off =
	// 无状态全量扫。开启后历史里逐字未变的内容命中缓存、跳过 detector,降低全量扫延迟。
	cacheOn := filterCacheEnabled()
	cacheWindow := filterCacheWindow()
	p.SetFilterCacheEnabled(cacheOn, cacheWindow)
	// 扫描角色策略(方案 §3.4):默认 user+assistant。assistant 必须在内 —— 响应侧
	// 占位符还原把原文交回客户端,下一轮它以 assistant 身份重发(见 filter_content.go)。
	scanRoles, rejectedRoles := p.SetFilterScanRoles(filterScanRoles())
	if len(rejectedRoles) > 0 {
		// 失败要显眼:不认识的角色名被丢弃,必须让运维看见,而不是静默按默认跑。
		slog.Warn("supervisor: unrecognized "+filterScanRolesEnv+" entries ignored",
			"event.name", "proxy.filter_scan_roles_invalid",
			"rejected", rejectedRoles, "applied", scanRoles)
	}
	// 工具块扫描档位(方案② 开关, 2026-08-10): 默认 audit = tool_result/tool_use 被
	// 扫描但动作封顶到"只记账"。off = 该策略行整体不生效(完全不抽取、不进 detector),
	// 给"慢机冷启动的额外 detector 往返不可接受"的现场使用。档位与动作上限同一字段,
	// 无法只开扫描不封顶 —— 见 filter_content.go toolBlockScanMode。
	toolBlocks, toolBlocksOK := proxy.SetToolBlockScanMode(filterToolBlockMode())
	if !toolBlocksOK {
		// 失败要显眼:拼错的档位不能静默按默认跑 —— 运维以为关掉了、实际还在扫,
		// 或反过来以为开着、实际漏扫,两个方向都必须看得见。
		slog.Warn("supervisor: unrecognized "+filterToolBlocksEnv+" value ignored",
			"event.name", "proxy.filter_tool_blocks_invalid",
			"raw", os.Getenv(filterToolBlocksEnv), "applied", toolBlocks)
	}
	slog.Info("supervisor: compliance filter hook active",
		"event.name", "proxy.filter_hook_active",
		"binary", binPath,
		"workers", m,
		"timeout_ms", filterTimeout().Milliseconds(),
		"incremental_scan", incremental,
		"content_hash_cache", cacheOn,
		"content_hash_cache_window", cacheWindow,
		"scan_roles", scanRoles,
		"tool_block_scan", toolBlocks)
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
		// G3: the user hasn't enabled the local filter, but the org may mandate it.
		// Spawn decision = user toggle (filter_stages) OR master mandate. When the
		// master forces compliance, run the detector even with no local filter_stages.
		if s.masterCompliance.Load() {
			if bin, sl := resolveAppBinary(s.appsDir(), []string{complianceDetectorSlug}); bin != "" {
				return bin, nil, sl, false
			}
			// Org MANDATES compliance but the detector binary is absent at the
			// canonical <apps_dir>/ai-compliance-detector/bin/ai-compliance-detector.
			// FAIL LOUD (declaredButMissing=true → 501) instead of serving
			// UNFILTERED. Pre-2026-06-12 this fell through to `false` and the proxy
			// silently passed traffic while the console showed compliance enabled
			// (虚假安全感). Confirmed broken end-to-end on staging: 政治敏感词
			// ("08宪章") sailed through BOTH fleet nodes (detector installed under
			// the WRONG slug "cluster-compliance") AND lobster de-proxies (no
			// detector). A missing detector under a mandate is a broken install,
			// not "no filter configured" — block until installed. Self-heals on the
			// next Reload once the installer lays the binary at the slug path.
			// Bug: workflow/CI/bugfix/20260612-compliance-chain-silently-bypassed.md
			slog.Error("supervisor: org mandates compliance but detector binary not found; "+
				"data-plane returns 501 until installed at <apps_dir>/"+complianceDetectorSlug+
				"/bin/"+complianceDetectorSlug,
				"event.name", "proxy.compliance_mandate_binary_missing",
				"apps_dir", s.appsDir(), "slug", complianceDetectorSlug)
			return "", nil, complianceDetectorSlug, true
		}
		return "", nil, "", false
	}
	if bin, sl := resolveAppBinary(s.appsDir(), slugs); bin != "" {
		return bin, nil, sl, false
	}
	return "", nil, "", true
}

// complianceDetectorSlug is the app slug force-spawned under a master mandate.
const complianceDetectorSlug = "ai-compliance-detector"

// appsDir is where `aikey app install` lays out app trees, derived from the
// vault path (<home>/.aikey/data/vault.db → <home>/.aikey/apps).
func (s *Supervisor) appsDir() string {
	return filepath.Join(filepath.Dir(filepath.Dir(s.cfg.Vault.Path)), "apps")
}

// resolveAppBinary returns the first existing <appsDir>/<slug>/bin/<slug> file
// and its slug, or ("","") if none. Pure (filesystem only) — unit-testable with
// a temp dir. The slug lets the caller read per-app vault config (e.g.
// filter_record_allow) for the binary it actually resolved.
func resolveAppBinary(appsDir string, slugs []string) (bin, slug string) {
	for _, s := range slugs {
		b := filepath.Join(appsDir, s, "bin", appBinaryFileName(s))
		if fi, err := os.Stat(b); err == nil && !fi.IsDir() {
			return b, s
		}
	}
	return "", ""
}

// appBinaryFileName returns the on-disk filename `aikey app install` lays an
// app's binary down as: "<slug>.exe" on Windows, "<slug>" elsewhere. The proxy
// MUST resolve the binary with the SAME OS-native name the installer wrote.
//
// Why this exists (bug 2026-06-23): the lookup used to be unconditionally
// extensionless (`bin/<slug>`). On Windows the installer lays the binary down as
// `<slug>.exe`, so os.Stat of the extensionless path always missed →
// resolveFilterBinary reported declaredButMissing=true → the supervisor latched
// fail-loud 501 (filterStub501Active) and the proxy refused ALL data-plane
// traffic the moment a user registered the compliance filter (`aikey app
// register --filter-stages ...`). I.e. installing the compliance plugin broke
// every LLM call on Windows. Linux/macOS were unaffected (no extension).
// Bugfix: workflow/CI/bugfix/2026-06-23-windows-filter-binary-missing-exe-501.md
func appBinaryFileName(slug string) string {
	if runtime.GOOS == "windows" {
		return slug + ".exe"
	}
	return slug
}

// filterTimeout resolves the per-Detect deadline: env override (ms) if a valid
// positive integer, else filterDefaultTimeout.
//
// An override BELOW the detector's own lane budget is honoured (operators own
// their boxes) but WARNed, because its practical effect is not "faster" but
// "silently unmasked" — see the filterDefaultTimeout note. 日志规范: a value that
// disables a safety control must never be accepted in silence.
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
	d := time.Duration(ms) * time.Millisecond
	if d <= detectorLaneDeadlineSmall {
		slog.Warn("supervisor: "+filterTimeoutMsEnv+" is at or below the detector's own per-lane deadline; "+
			"Detect will be cut short before the detector can finish, degrading to fail-open (nothing masked) "+
			"instead of running faster. Raise it above the lane budget plus IPC margin.",
			"event.name", "proxy.filter_timeout_below_detector_budget",
			"configured_ms", ms,
			"detector_lane_deadline_ms", detectorLaneDeadlineSmall.Milliseconds(),
			"recommended_min_ms", filterDefaultTimeout.Milliseconds())
	}
	return d
}

// filterIncrementalScanEnv toggles latest-user-turn-only scanning. Opt-in
// (default off = full scan); the form-② lobster install sets it to 1. Accepts
// 1/true/yes (case-insensitive).
const filterIncrementalScanEnv = "AIKEY_PROXY_FILTER_INCREMENTAL_SCAN"

func filterIncrementalScan() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(filterIncrementalScanEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// filterCacheEnv toggles the inbound-filter content-hash cache (设计 §4). DEFAULT ON
// (用户 2026-06-17:复用记忆默认开启) — it replaces the deprecated incremental scan as
// the standing latency optimization, and is REQUIRED for digital-employee long
// conversations to hold the 15ms SLO (full re-scan of a 40-msg history ≈ 50ms; cache
// keeps it ~1.3ms). Explicit opt-out only: 0/false/no/off (case-insensitive). Safe to
// default on — the history-leak fix (full user coverage) is unconditional regardless.
const filterCacheEnv = "AIKEY_PROXY_FILTER_CACHE"

func filterCacheEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(filterCacheEnv))) {
	case "0", "false", "no", "off":
		return false // explicit opt-out
	default:
		return true // default on (incl. unset)
	}
}

// complianceDisabledEnv is the operator on/off switch for the WHOLE compliance filter
// (lives in de-proxy.env, 用户 2026-06-17). "off" → installFilterHook installs no hook
// and does NOT fail-loud (501), so an operator can toggle compliance with one line + a
// restart, without uninstalling the detector. Default (unset / "on") → normal wiring.
const complianceDisabledEnv = "AIKEY_DE_COMPLIANCE"

func complianceDisabledByOperator() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(complianceDisabledEnv))) {
	case "off", "0", "false", "no", "disabled":
		return true
	default:
		return false // default on (incl. unset / "on")
	}
}

// filterScanRolesEnv overrides which chat message roles the inbound compliance
// filter scans — comma-separated, e.g. "user,assistant,tool". Unset (the normal
// case) → the proxy's default {user, assistant}.
//
// WHY a knob rather than a constant (方案 §3.4): the role set is the axis that
// changed on both compliance incidents (2026-06-16 history leak, 2026-08-08
// restore leak), and tool/function output is the next open question. An operator
// facing a shape we have not shipped support for can widen the set without a
// release. Narrowing is possible too but dangerous: dropping "assistant" reopens
// the restore leak, which is why the E2E fence asserts it goes RED when removed.
//
// Unrecognized names are rejected + WARNed; an entry list with nothing valid in
// it keeps the default (a typo must not silently disable scanning).
const filterScanRolesEnv = "AIKEY_PROXY_FILTER_SCAN_ROLES"

// filterScanRoles parses the comma-separated env override. Empty/unset → nil,
// which the proxy reads as "use the default policy".
func filterScanRoles() []string {
	raw := strings.TrimSpace(os.Getenv(filterScanRolesEnv))
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// filterToolBlocksEnv sets the scan rung for agent tool traffic (tool_result /
// tool_use): "audit" (default — scanned, every verdict capped to an event) or
// "off" (the policy rows do not apply at all; nothing is extracted).
//
// WHY a knob (用户 2026-08-10, same request shape as the CN_ADDRESS lane switch):
// opening tool blocks costs one extra detector round-trip per block on the
// request hot path. That is absorbed by the content-hash cache in steady state,
// but a cold start on a slow box pays it in full, and an operator for whom that
// latency is unacceptable must be able to turn the SCOPE off without turning
// compliance off. Narrowing is the dangerous direction here — off restores the
// audit blind spot proven by aikey-test/auditeye/tool_result_scope_test.go
// arms B/C — so it is opt-in, never the default, and the effective rung is
// published on the diagnostics mask_restore block (`tool_block_scan`).
//
// Unrecognized values keep the DEFAULT rung and are WARNed: a typo must not
// silently change what compliance can see, in either direction.
const filterToolBlocksEnv = "AIKEY_PROXY_FILTER_TOOL_BLOCKS"

// filterToolBlockMode returns the raw env rung. Empty/unset → "", which the
// proxy reads as "use the default rung".
func filterToolBlockMode() string {
	return strings.TrimSpace(os.Getenv(filterToolBlocksEnv))
}

// filterCacheWindowEnv sets the per-session cache window (last-N piece verdicts;
// 设计 §4 / 用户 2026-06-16:默认 5,可配). 0 / invalid → proxy uses its default.
const filterCacheWindowEnv = "AIKEY_PROXY_FILTER_CACHE_WINDOW"

func filterCacheWindow() int {
	if v := strings.TrimSpace(os.Getenv(filterCacheWindowEnv)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 0 // 0 → proxy uses defaultMaskCacheWindow
}

// filterReadyTimeout resolves the detector spawn ready deadline: env override
// (ms) if a valid positive integer, else filterDefaultReadyTimeout.
func filterReadyTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv(filterReadyTimeoutMsEnv))
	if raw == "" {
		return filterDefaultReadyTimeout
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		slog.Warn("supervisor: invalid "+filterReadyTimeoutMsEnv+"; using default",
			"event.name", "proxy.filter_ready_timeout_invalid", "value", raw)
		return filterDefaultReadyTimeout
	}
	return time.Duration(ms) * time.Millisecond
}

// filterWorkersEnv sets M, the number of independent detector PROCESSES the pool
// spawns. Default 1 (Personal/Trial — behavior unchanged). Production sets 2 for
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
	// Cluster nodes have NO Personal config.json (no `aikey login` — the proxy
	// runs as the `aikey` system user, home /home/aikey, no .aikey/config). They
	// are configured via env (/etc/aikey/cluster-node.env), exactly as
	// complianceOrgID() reads AIKEY_HUB_ORG_ID. Prefer the cluster control-URL
	// env; fall back to the Personal config.json for Personal/Trial. WHY: without
	// the env path readControlPanelURL()=="" on cluster nodes, so BOTH the
	// compliance and conversation-audit master-policy polls early-return —
	// conversation-audit (no local-toggle fallback) then never turns capture on.
	// Bugfix: 2026-06-17-conversation-audit-cluster-control-url-env.md
	if v := strings.TrimRight(os.Getenv("AIKEY_HUB_CONTROL_URL"), "/"); v != "" {
		return v
	}
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
