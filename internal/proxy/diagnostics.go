// diagnostics.go — read-only pipeline diagnostics endpoint (task 7.9) and the
// single source-of-truth model-mapping health judgment (task 3.5).
//
// GET /v1/diagnostics/pipeline exposes, WITHOUT mutating anything:
//   - registry provenance: the embedded provider_fingerprint digest, the route
//     row count, and which providers carry a model_map ("mapping comes from
//     registry vX" — the read-only visibility that replaced the deleted P5 UI).
//   - model-mapping runtime health: a 3-state verdict + the counters + the last
//     "configured but not effective" occurrence, so the four surfaces (web
//     banner / aikey doctor / aikey test / ak use) can all answer "was a mapping
//     configured but not taking effect?" from ONE function (mappingHealth), never
//     an inlined marker string per caller (3.5 hard rule).
//   - compliance mask-placeholder fidelity (P2, 方案 20260808 §3.2 L3): issued
//     vs restored placeholder counts + a 3-state verdict. This is the only
//     signal that surfaces "some model started rewriting our placeholders" —
//     every such request still returns 200, so without an externally readable
//     counter the degradation is invisible (health-signal-surface §H1).
//   - the generation ID these counters belong to. Every counter on this
//     endpoint is GENERATION-scoped, not process-scoped: the proxy hot-reloads
//     in-process, keeping its PID while replacing the *Proxy that owns the
//     counters. Publishing the generation is what makes that reset externally
//     observable instead of an invisible re-zeroing under a live PID.
//
// 🔴 GET-only + read-only (design P5-deletion note: status endpoints must not
// mutate). Health signals must be externally readable (observability §H1/H2).
package proxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/pkg/providerroutes"
)

// MappingStatus is the 3-state model-mapping verdict. Stable string values so
// every surface (web/doctor/test/ak use) renders the same three states.
type MappingStatus string

const (
	// MappingInactive: no model_map is configured in the live registry at all —
	// mapping simply isn't in play (not an error; the banner stays silent).
	MappingInactive MappingStatus = "inactive"
	// MappingOK: mappings are configured and applying cleanly (no recent misses).
	MappingOK MappingStatus = "ok"
	// MappingDegraded: a model_map IS configured but the MOST RECENT relevant
	// event was a passthrough-miss (a request slipped past unchanged) newer than
	// the last successful apply — the "配置了但没生效" case the four surfaces warn
	// on. Recoverable: a later successful apply clears it. A reject does NOT
	// count (unmatched=reject policy WORKING is not a degradation).
	MappingDegraded MappingStatus = "degraded"
)

// PipelineDiagnostics is the read-only payload of /v1/diagnostics/pipeline.
//
// MaskRestore was ADDED here rather than behind a new endpoint (慎重新建
// API/接口协议): this endpoint already is the proxy's read-only "is the request
// pipeline behaving?" surface, an additive field costs no new route, no new
// auth posture and no new client contract, and the two blocks are read by the
// same operator in the same breath.
type PipelineDiagnostics struct {
	Registry RegistryProvenance `json:"registry"`
	// GenerationID scopes EVERY counter below it.
	//
	// The proxy hot-reloads in-process: `aikey` config/vault changes make the
	// supervisor build a NEW generation (supervisor.buildGeneration → new
	// *Proxy) and swap it in behind the same listener. The PID does not change,
	// the process uptime does not reset — but `model_mapping.applied/rejected/
	// passthrough_missing` and `mask_restore.placeholders_issued/restored` all
	// restart at zero, because they live on the Proxy that was just replaced.
	//
	// Without this field an external reader (release E2E, ops probe, dashboard)
	// has NO way to tell a fresh low number from a genuine cumulative one, so a
	// reload between two polls silently invalidates any assertion built on the
	// deltas — and it fails in the reassuring direction (counters look calm).
	// Compare it across reads: same ID → the counters are comparable; changed ID
	// → they were zeroed in between and the earlier sample must be discarded.
	//
	// Additive scalar rather than a new endpoint or a new nested object
	// (慎重新建 API/接口协议): it annotates the numbers already served here.
	// 0 = no supervisor wired this Proxy (unit tests / embedded use); real
	// supervisor generations start at 1.
	GenerationID int64             `json:"generation_id"`
	ModelMapping MappingHealth     `json:"model_mapping"`
	MaskRestore  MaskRestoreHealth `json:"mask_restore"`
	// FilterHook is the filter child-process health projection + the verdict
	// cache's current cacheability. Additive block on this endpoint rather than a
	// new route, for the same reasons MaskRestore was (慎重新建 API/接口协议) —
	// and read in the same breath: "is the detector answering, and is the proxy
	// still allowed to reuse its verdicts?" is one question for an operator.
	//
	// 🔴 NOT generation-scoped, unlike every counter above it: this block is a
	// point-in-time projection of live child state, not a cumulative count. It is
	// therefore safe to read on its own without comparing GenerationID.
	FilterHook FilterHookHealth `json:"filter_hook"`
}

// FilterHookStatus is the filter dispatcher's 4-state verdict. `partial` exists
// as a state of its own precisely BECAUSE apphook.FilterPool.Status() cannot
// express it: that aggregate answers Healthy=true whenever ≥1 worker survives,
// which is right for "keep serving" and a false green for "is this healthy?".
type FilterHookStatus string

const (
	// FilterHookInactive: no filter hook is installed on this proxy generation
	// (the common Personal default — compliance detection not enabled). Not a
	// fault; the dispatcher is a no-op and pays nothing.
	FilterHookInactive FilterHookStatus = "inactive"
	// FilterHookOK: every unit behind the hook is healthy.
	FilterHookOK FilterHookStatus = "ok"
	// FilterHookPartial: SOME units are healthy and some are not. 🔴 THE STATE
	// THIS BLOCK EXISTS FOR, because the pool's own Status() cannot express it.
	//
	// What it costs changed on 2026-08-14 (B39 data-plane fix): dispatch now
	// SKIPS unfit workers, so coverage is intact — content is still inspected by
	// the survivors. What is lost is headroom: the pool is running below the
	// process count the operator provisioned, the survivors carry the whole load,
	// and the cross-process fault isolation the pool exists for is partly gone.
	// Before that fix this state also meant "≈1/M of all requests are forwarded
	// un-inspected" (measured live: 4 of 12 on a 3-worker pool).
	//
	// Reachable only for M>1 pools (Production / Cluster).
	FilterHookPartial FilterHookStatus = "partial"
	// FilterHookDegraded: NO unit is healthy — nothing is being inspected at all.
	// For the M=1 deployments (Personal / Trial) this is the only failure state,
	// and DegradedReason on the single worker is what tells "wedged mid-write"
	// (write_timeout) apart from "never started" (not_started).
	FilterHookDegraded FilterHookStatus = "degraded"
)

// VerdictCacheStatus is the per-piece verdict cache's current usability.
type VerdictCacheStatus string

const (
	// VerdictCacheDisabled: the cache is not configured on this generation
	// (AIKEY_PROXY_FILTER_CACHE off). Every piece is scanned by design.
	VerdictCacheDisabled VerdictCacheStatus = "disabled"
	// VerdictCacheActive: configured AND the hook can state which content set is
	// live, so verdicts are being memoized under that epoch.
	VerdictCacheActive VerdictCacheStatus = "active"
	// VerdictCacheSuspended: configured but SWITCHED OFF at runtime because the
	// hook cannot state its effective content set (apphook.CacheEpoch's fail-safe
	// branch). Correctness is intact — every piece is really scanned — but the
	// hit rate goes to zero and latency rises with no other outward sign.
	VerdictCacheSuspended VerdictCacheStatus = "suspended"
)

// FilterWorkerHealth is ONE independently-failing filter unit.
//
// Privacy: process health only. No payload, no finding, no rule — this block is
// about whether the inspector is alive, never about what it inspected.
type FilterWorkerHealth struct {
	// Index is the unit's dispatch position (apphook.FilterPool round-robins over
	// this order), so `index: 1` of a 2-worker pool means "≈half the traffic".
	Index int `json:"index"`
	// DegradedReason is the child's own enumerated cause, populated iff
	// !Healthy: not_started | not_installed: … | write_timeout | write_failed: … |
	// read_failed: … | ready_timeout | listpacks_failed: … | restarting | crash.
	// This is the field whose absence made `ak doctor` unable to tell a wedged
	// child from one that never started (review findings B5/B36).
	DegradedReason string `json:"degraded_reason,omitempty"`
	// Version is the child's binary/protocol version from its ready sentinel.
	Version string `json:"version,omitempty"`
	// ContentVersion is the token for the ruleset this unit currently detects
	// with; empty when unknown, in which case ContentVersionReason names why (an
	// apphook.ContentVersionReason* value).
	ContentVersion       string `json:"content_version,omitempty"`
	ContentVersionReason string `json:"content_version_reason,omitempty"`
	RestartCount         uint64 `json:"restart_count"`
	Healthy              bool   `json:"healthy"`
}

// VerdictCacheHealth explains whether per-piece verdicts are being reused, and
// when they are not, WHICH remedy applies.
type VerdictCacheHealth struct {
	Status VerdictCacheStatus `json:"status"`
	// Reason is a terse, surface-agnostic sentence rendered verbatim by callers.
	Reason string `json:"reason"`
	// Cause is the enumerated apphook.ContentVersionReason* behind a `suspended`
	// verdict — the machine-readable half that decides whether the operator needs
	// a RESTART (child_degraded) or an UPGRADE (unsupported_op_list_packs).
	//
	// It is computed HERE, not by each reader, for the same reason mappingHealth
	// is: a pool's units can be blind for different reasons at once, and the
	// precedence between them is one rule that must have one implementation.
	Cause string `json:"cause,omitempty"`
	// ContentVersion is the epoch verdicts are currently keyed under (`active`).
	ContentVersion string `json:"content_version,omitempty"`
}

// FilterHookHealth is the externally readable filter-pipeline health signal.
//
// WHY IT EXISTS (2026-08-13, review findings B5 / B36 / B6). apphook.Status
// already carried Healthy / DegradedReason / RestartCount, and every one of them
// went to a `slog` line and nowhere else — the struct did not even have json
// tags. So the 2026-08-13 childhook write-timeout fix introduced `write_timeout`,
// a new and important degraded cause, with no external出口: `ak doctor` could
// only observe `available:false` on /admin/compliance/packs and had to conflate
// "the child wedged" with "the child never started", losing the cause and the
// remedy. 健康信号必须可被外部读取 — a signal that only exists in a log file is
// not a health signal.
type FilterHookHealth struct {
	Status FilterHookStatus `json:"status"`
	Reason string           `json:"reason"`
	// Name is the app identifier (apphook.Hook.Name), e.g.
	// "ai-compliance-detector". Reported, never branched on — the proxy must not
	// know what business the child does (apphook.go invariant #16).
	Name string `json:"name,omitempty"`
	// WorkersHealthy / WorkersTotal are the counts a surface can render without
	// walking Workers. 1/1 on Personal and Trial; M is the pool size elsewhere.
	WorkersHealthy int                  `json:"workers_healthy"`
	WorkersTotal   int                  `json:"workers_total"`
	Workers        []FilterWorkerHealth `json:"workers"`
	VerdictCache   VerdictCacheHealth   `json:"verdict_cache"`
}

// contentVersionCausePrecedence orders the reasons a unit can be blind, most
// actionable first. Used to pick ONE cause for a pool whose units are blind for
// different reasons.
//
// `unsupported_op_list_packs` wins because it is the only one that never
// self-heals: the child is alive and serving, and the cache stays off until
// someone upgrades the detector binary. Reporting a transient `first_poll_pending`
// from a sibling worker instead would tell the operator to wait for something
// that will never arrive.
var contentVersionCausePrecedence = []string{
	apphook.ContentVersionReasonUnsupported,
	apphook.ContentVersionReasonChildDegraded,
	apphook.ContentVersionReasonPollFailed,
	apphook.ContentVersionReasonPollPending,
}

// filterHookHealth is the ONE function every surface consults for filter-pipeline
// health (same posture as mappingHealth / maskRestoreHealth). Pure read; safe to
// call concurrently and cheap enough for a diagnostics GET (it touches only
// atomics inside the hook).
func (p *Proxy) filterHookHealth() FilterHookHealth {
	hook := p.filterHook
	if hook == nil {
		return FilterHookHealth{
			Status:  FilterHookInactive,
			Reason:  "No filter hook is installed on this proxy generation — inbound content is not inspected.",
			Workers: []FilterWorkerHealth{},
			VerdictCache: VerdictCacheHealth{
				Status: VerdictCacheDisabled,
				Reason: "No filter hook, so there are no verdicts to memoize.",
			},
		}
	}

	// apphook.WorkerStatuses is the sanctioned enumeration: a single ChildHook
	// comes back as a pool of one, so this loop has no "is it a pool?" branch.
	statuses := apphook.WorkerStatuses(hook)
	h := FilterHookHealth{
		Name:         hook.Name(),
		WorkersTotal: len(statuses),
		Workers:      make([]FilterWorkerHealth, 0, len(statuses)),
	}
	for i, s := range statuses {
		if s == nil {
			continue
		}
		if s.Healthy {
			h.WorkersHealthy++
		}
		h.Workers = append(h.Workers, FilterWorkerHealth{
			Index:                i,
			Healthy:              s.Healthy,
			DegradedReason:       s.DegradedReason,
			RestartCount:         s.RestartCount,
			Version:              s.Version,
			ContentVersion:       s.ContentVersion,
			ContentVersionReason: s.ContentVersionReason,
		})
	}

	switch {
	case h.WorkersTotal == 0:
		h.Status = FilterHookDegraded
		h.Reason = "The filter hook reports no units at all — nothing can inspect inbound content."
	case h.WorkersHealthy == 0:
		h.Status = FilterHookDegraded
		h.Reason = fmt.Sprintf("No filter unit is answering (0/%d) — inbound content is forwarded un-inspected (fail-open).", h.WorkersTotal)
	case h.WorkersHealthy < h.WorkersTotal:
		// 🔴 The pool's own Status() calls this healthy. It is not — see
		// FilterHookPartial. Reason states the CURRENT consequence: since the B39
		// fix, dispatch skips the unfit units, so what is lost is headroom and
		// isolation rather than coverage. This sentence is the single source every
		// surface renders verbatim (`ak doctor` included) — if the dispatch
		// behavior changes again, it changes here and nowhere else.
		h.Status = FilterHookPartial
		h.Reason = fmt.Sprintf("Only %d of %d filter units are answering. Dispatch skips the unfit units, so content is still inspected — but the pool is below its provisioned process count and the survivors carry all of the load.", h.WorkersHealthy, h.WorkersTotal)
	default:
		h.Status = FilterHookOK
		h.Reason = fmt.Sprintf("All %d filter unit(s) answering.", h.WorkersTotal)
	}

	h.VerdictCache = p.verdictCacheHealth(hook, h.Workers)
	return h
}

// verdictCacheHealth derives whether per-piece verdicts are currently reusable.
// It asks apphook.CacheEpoch — the SAME call the dispatcher makes per request —
// so the endpoint can never claim the cache is on while the data plane has it
// off (health-signal-surface: report what the main path actually does).
func (p *Proxy) verdictCacheHealth(hook apphook.Hook, workers []FilterWorkerHealth) VerdictCacheHealth {
	if p.filterCache == nil {
		return VerdictCacheHealth{
			Status: VerdictCacheDisabled,
			Reason: "The per-piece verdict cache is not enabled on this proxy (AIKEY_PROXY_FILTER_CACHE off) — every content piece is scanned.",
		}
	}
	epoch, cacheable := apphook.CacheEpoch(hook)
	if cacheable {
		return VerdictCacheHealth{
			Status:         VerdictCacheActive,
			Reason:         "Verdicts are being reused within the current ruleset epoch.",
			ContentVersion: epoch,
		}
	}
	cause := dominantContentVersionCause(workers)
	v := VerdictCacheHealth{Status: VerdictCacheSuspended, Cause: cause}
	switch cause {
	case apphook.ContentVersionReasonUnsupported:
		// The B6 state: correct behavior, previously invisible. Say the cost AND
		// the remedy — an operator who only reads "the proxy got slower" has no
		// path from the symptom to `aikey app install`.
		v.Reason = "Verdict caching is OFF because the detector build cannot report which ruleset it is using (it does not answer op=ListPacks). " +
			"Every content piece is re-scanned, so filter latency is at its cold-path cost. Upgrade the detector to restore caching."
	case apphook.ContentVersionReasonChildDegraded:
		v.Reason = "Verdict caching is OFF because the filter child is degraded and cannot vouch for its ruleset. It clears when the child recovers."
	case apphook.ContentVersionReasonPollPending:
		v.Reason = "Verdict caching is OFF until the first effective-content poll returns (self-clearing, within one poll interval)."
	default:
		v.Reason = "Verdict caching is OFF because the filter hook cannot state its effective content set; every content piece is re-scanned."
	}
	return v
}

// noteVerdictCacheState logs the verdict cache switching off (and back on) from
// the point of view of a REAL request, exactly once per transition.
//
// 🔴 WHY IT LIVES ON THE REQUEST PATH AT ALL, given the poll already WARNs. The
// poll's WARN (EventAppHookContentVersionUnknown) is raised on a background
// goroutine with no request context, so it can carry neither request_id nor
// trace_id — and the operator symptom is "requests got slower", which is a
// per-request observation. 日志规范 asks the CONSUMER of a degraded signal to
// raise its own line rather than rely on the producer's; this is that line, and
// it adds the enumerated cause that decides restart-vs-upgrade.
//
// 🔴 WHY IT IS LATCHED. The suspended state persists — a detector build that
// cannot answer op=ListPacks never begins to — so an unlatched line would emit
// at request rate for the life of the deployment. CompareAndSwap makes the
// concurrent-request race benign: exactly one goroutine wins the transition and
// logs, the rest see the new value and stay silent.
//
// Never returns an error and never affects the verdict — pure observation.
func (p *Proxy) noteVerdictCacheState(logger *slog.Logger, hook apphook.Hook, cacheable bool) {
	if !cacheable {
		if p.filterCacheSuspended.CompareAndSwap(false, true) {
			// The reason/cause come from the SAME derivation the diagnostics
			// endpoint publishes, so the log line and `filter_hook.verdict_cache`
			// can never tell an operator two different stories.
			h := p.filterHookHealth()
			logger.Warn("filter: verdict cache SUSPENDED — the filter hook cannot state its effective content set, so every content piece is re-scanned",
				"event.name", observability.EventProxyFilterVerdictCacheSuspended,
				"hook", hook.Name(),
				"cause", h.VerdictCache.Cause,
				"workers_healthy", h.WorkersHealthy,
				"workers_total", h.WorkersTotal,
				"remedy", h.VerdictCache.Reason)
		}
		return
	}
	if p.filterCacheSuspended.CompareAndSwap(true, false) {
		logger.Info("filter: verdict cache RESUMED — the filter hook can state its effective content set again",
			"event.name", observability.EventProxyFilterVerdictCacheResumed,
			"hook", hook.Name())
	}
}

// dominantContentVersionCause picks the one cause to report for a hook whose
// units are blind for different reasons. See contentVersionCausePrecedence.
func dominantContentVersionCause(workers []FilterWorkerHealth) string {
	present := make(map[string]struct{}, len(workers))
	for i := range workers {
		if r := workers[i].ContentVersionReason; r != "" {
			present[r] = struct{}{}
		}
	}
	for _, c := range contentVersionCausePrecedence {
		if _, ok := present[c]; ok {
			return c
		}
	}
	// A cause outside the enum (a future Hook implementation) must still be
	// reported rather than swallowed — 禁止静默 return 默认值.
	for i := range workers {
		if r := workers[i].ContentVersionReason; r != "" {
			return r
		}
	}
	return ""
}

// MaskRestoreStatus is the compliance-placeholder fidelity verdict. The first
// three values are the same strings as MappingStatus so every surface renders
// both blocks with one switch; `insufficient_sample` is specific to this signal
// because it is the only one with a sample floor.
type MaskRestoreStatus string

const (
	// MaskRestoreInactive: this process has never issued a mask placeholder —
	// compliance masking is off, or no traffic hit a restorable entity.
	MaskRestoreInactive MaskRestoreStatus = "inactive"
	// MaskRestoreOK: placeholders are coming back and being restored.
	MaskRestoreOK MaskRestoreStatus = "ok"
	// MaskRestoreInsufficientSample: placeholders HAVE been issued, but too few
	// to judge the ratio. Distinct from `ok` on purpose — this state used to be
	// folded into it, so a proxy at 0% fidelity on a sample of one reported
	// "placeholders are being returned and restored", contradicting its own
	// numbers (2026-08-10). Distinct from `inactive` too: inactive means the
	// feature never ran, this means it ran and the verdict is pending.
	MaskRestoreInsufficientSample MaskRestoreStatus = "insufficient_sample"
	// MaskRestoreDegraded: enough placeholders have been issued to judge, and
	// the models are returning too few of them intact — i.e. users are seeing
	// `{{ADDR_1}}` instead of their own text. NOT an error path: the request
	// succeeded, the mask worked, only the convenience half is failing.
	MaskRestoreDegraded MaskRestoreStatus = "degraded"
)

const (
	// maskFidelityMinSample: below this many issued placeholders the ratio is
	// noise (one unlucky answer would read as 0%), so the verdict is withheld
	// as MaskRestoreInsufficientSample rather than asserted as `ok`.
	maskFidelityMinSample = 20
	// maskFidelityDegradedPct: the L3 defenses (template-syntax placeholder +
	// tolerant matching) are designed to make near-100% the normal reading; a
	// sustained drop below this means some model started rewriting placeholders
	// and the mask/restore feature is silently degrading for its users.
	maskFidelityDegradedPct = 80
)

// MaskRestoreHealth is the externally-readable 保真率 signal (方案 20260808
// §3.2 L3).
//
// 🔴 Issued/Restored are cumulative for the GENERATION, not for the process
// lifetime. This comment used to claim "process lifetime" and that was wrong:
// the proxy hot-reloads in-process (supervisor.buildGeneration constructs a new
// *Proxy behind the same PID and listener), and these counters live on the
// Proxy, so a reload resets them to zero with no visible restart. Read them
// together with PipelineDiagnostics.GenerationID — that ID is what tells a
// caller whether two samples belong to the same counting epoch.
//
// The verdict is derived, never latched — a model that starts behaving again
// pulls the ratio back up (health-signal-surface: report the current state, not
// a terminal one).
//
// Privacy: counts only. No label, no entity code, no length, no text — the
// placeholder↔original mapping never leaves request memory (B3 拍板).
type MaskRestoreHealth struct {
	Status MaskRestoreStatus `json:"status"`
	Reason string            `json:"reason"`
	// ScanRoles is the effective inbound scan-role policy (方案 §3.4). It lives in
	// THIS block — not a config dump — because restore and scan-scope are one
	// safety property: restoration hands the plaintext back to the client, and it
	// only stays out of the upstream on the next turn because `assistant` is
	// scanned. An operator (or the release E2E) must be able to READ that from
	// outside the process, not infer it from a startup log line
	// (health-signal-surface). Counts + this list answer "is mask/restore whole?".
	ScanRoles []string `json:"scan_roles"`
	// ToolBlockScan is the effective rung for agent tool traffic
	// (off|audit — see toolBlockScanMode). It sits next to ScanRoles for the
	// same reason: it is scan SCOPE, and an operator who turned it off has
	// changed what compliance can see. A rung that only exists in a startup log
	// line is not externally readable (health-signal-surface), and a silently
	// off lane makes every downstream audit assertion vacuously green.
	ToolBlockScan string `json:"tool_block_scan"`
	// TruncatedPieces / SkippedBytes quantify the OTHER scan-scope hole: content
	// pieces longer than the detector input cap (pipeInputCap, 16 KiB) are scanned
	// only up to the cap, and the remainder is forwarded to the upstream LLM
	// uninspected (bugfix 2026-08-13 20260813-pipe-input-cap-truncates-silently).
	//
	// They live in THIS block for the same reason ScanRoles and ToolBlockScan do:
	// all four are compliance scan SCOPE — the answer to "what did the detector
	// actually get to look at?". Read them WITH the audit-coverage numbers on the
	// compliance dashboard: a non-zero SkippedBytes means those numbers are a
	// lower bound, not a measurement, and agent tool traffic crosses the cap
	// routinely rather than exceptionally.
	//
	// Additive scalars rather than a new endpoint or a new nested block
	// (慎重新建 API/接口协议), matching the precedent set by ScanRoles/ToolBlockScan.
	//
	// 🔴 They deliberately do NOT feed Status. Status is the placeholder-fidelity
	// verdict that four surfaces (web banner / doctor / test / ak use) already
	// render; folding a second, unrelated failure mode into it would change what
	// an existing green/red means for every one of them. Whether truncation should
	// get a verdict of its own is left open — see the bugfix record.
	//
	// 🔴 Generation-scoped like Issued/Restored: compare across reads using
	// PipelineDiagnostics.GenerationID.
	TruncatedPieces int64 `json:"scan_truncated_pieces"`
	SkippedBytes    int64 `json:"scan_skipped_bytes"`
	Issued          int64 `json:"placeholders_issued"`
	Restored      int64  `json:"placeholders_restored"`
	FidelityPct   int    `json:"fidelity_pct"`
}

// maskRestoreHealth is the ONE function every surface consults for placeholder
// fidelity (same posture as mappingHealth). Pure read; safe to call concurrently.
func (p *Proxy) maskRestoreHealth() MaskRestoreHealth {
	issued := p.maskFidelity.issued.Load()
	restored := p.maskFidelity.restored.Load()
	h := MaskRestoreHealth{
		Issued:        issued,
		Restored:      restored,
		ScanRoles:     p.filterScanRoles.list(),
		ToolBlockScan: ToolBlockScanMode(),
		// Populated in the literal, BEFORE the early returns below: coverage
		// truncation is independent of whether any placeholder was ever issued, so
		// a deployment that has never masked anything (Status=inactive — the most
		// common state) must still report how much content it skipped. Setting it
		// only on the ok/degraded paths would hide the number in exactly the
		// deployments least likely to be watching for it.
		TruncatedPieces: p.scanCoverage.truncatedPieces.Load(),
		SkippedBytes:    p.scanCoverage.skippedBytes.Load(),
	}
	if issued <= 0 {
		h.Status = MaskRestoreInactive
		h.Reason = "No compliance mask placeholder has been issued by this proxy."
		return h
	}
	h.FidelityPct = int(restored * 100 / issued)
	if issued >= maskFidelityMinSample {
		if h.FidelityPct < maskFidelityDegradedPct {
			h.Status = MaskRestoreDegraded
			h.Reason = "Models are returning too few mask placeholders intact — users are seeing placeholders instead of their own text."
			return h
		}
		h.Status = MaskRestoreOK
		h.Reason = "Mask placeholders are being returned by the models and restored."
		return h
	}

	// Below the sample floor the ratio is noise, so no verdict is available —
	// and "no verdict" must not be dressed up as a healthy one.
	//
	// It used to fall through to MaskRestoreOK: with issued=1 / restored=0 the
	// endpoint reported status=ok and the sentence "Mask placeholders are being
	// returned by the models and restored." at 0% fidelity — a health signal
	// stating the exact opposite of its own measurement (observed 2026-08-10
	// while building the pipe-wire E2E). A reader who trusts it stops looking,
	// which is the whole failure mode a health surface exists to prevent.
	// Reporting the counters plus "not enough data" keeps the number visible
	// and the claim honest.
	h.Status = MaskRestoreInsufficientSample
	h.Reason = fmt.Sprintf("Only %d placeholder(s) issued — below the %d-sample floor, so fidelity (%d%%) is not yet a verdict.",
		issued, maskFidelityMinSample, h.FidelityPct)
	return h
}

// RegistryProvenance proves WHICH embedded registry is live (P7.14: the digest
// changes only when the binary does — editing a mapping line is a re-release).
type RegistryProvenance struct {
	Digest                string   `json:"digest"`
	RouteRows             int      `json:"route_rows"`
	ProvidersWithModelMap []string `json:"providers_with_model_map"`
}

// MappingHealth is the single source-of-truth verdict + evidence. `Reason` is a
// terse, surface-agnostic sentence the callers render verbatim.
type MappingHealth struct {
	Status             MappingStatus  `json:"status"`
	Reason             string         `json:"reason"`
	Applied            int64          `json:"applied"`
	Rejected           int64          `json:"rejected"`
	PassthroughMissing int64          `json:"passthrough_missing"`
	LastMiss           *mapMissRecord `json:"last_miss,omitempty"`
}

// mappingHealth is the ONE function every surface consults (3.5: 🚫 no per-caller
// inlined marker strings). It reads the live registry + the runtime counters and
// returns the 3-state verdict. Pure read; safe to call concurrently.
func (p *Proxy) mappingHealth() MappingHealth {
	applied := p.mapApplied.Load()
	rejected := p.mapRejected.Load()
	passthrough := p.mapPassthrough.Load()
	last := p.lastMapMiss.Load()
	missNano := p.lastMapMissNano.Load()
	applyNano := p.lastMapApplyNano.Load()

	hasMappings := len(provider.Routes().AllModelMaps()) > 0
	h := MappingHealth{
		Applied:            applied,
		Rejected:           rejected, // kept for visibility; deliberately OUT of the verdict
		PassthroughMissing: passthrough,
		LastMiss:           last,
	}
	switch {
	case !hasMappings:
		h.Status = MappingInactive
		h.Reason = "No model mapping is configured in this build's registry."
	case missNano > applyNano:
		// RECOVERABLE, not a monotonic latch (health-signal-surface: assert
		// transition, not terminal): degraded only while the most-recent
		// passthrough-miss is newer than the most-recent successful apply — the
		// CURRENT state. A later apply (applyNano advances) flips this back to
		// ok. A `reject` (unmatched=reject policy WORKED) never stamps missNano,
		// so a working reject policy is NOT degraded.
		h.Status = MappingDegraded
		h.Reason = "A model mapping is configured but recent requests did not match it — the mapping may not be taking effect for this client."
	default:
		h.Status = MappingOK
		h.Reason = "Model mapping is configured and applying."
	}
	return h
}

// handleDiagnosticsPipeline serves GET /v1/diagnostics/pipeline. Read-only.
func (p *Proxy) handleDiagnosticsPipeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
			"METHOD_NOT_ALLOWED", "This diagnostics endpoint is read-only (GET).")
		return
	}

	tbl := provider.Routes()
	provs := make([]string, 0)
	for _, m := range tbl.AllModelMaps() {
		if m.Provider != "" {
			provs = append(provs, m.Provider)
		}
	}
	sort.Strings(provs)

	out := PipelineDiagnostics{
		Registry: RegistryProvenance{
			Digest:                providerroutes.Digest(),
			RouteRows:             tbl.Len(),
			ProvidersWithModelMap: provs,
		},
		GenerationID: p.GenerationID(),
		ModelMapping: p.mappingHealth(),
		MaskRestore:  p.maskRestoreHealth(),
		FilterHook:   p.filterHookHealth(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}
