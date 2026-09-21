// filter_dispatch.go — P4 filter dispatcher.
//
// Wires a generic apphook.Hook (ai-compliance-detector / DLP / etc.) into the
// proxy's outbound forwarding path. This is the real implementation of the
// SPEC §1.5.7 filter chain that P3 stubbed with filterStub501Active.
//
// Design note — apphook IS the dispatcher:
//
//	SPEC §1.5 originally described a Unix-socket + msgpack filter protocol.
//	That design was superseded by the "proxy is a generic app host" decision
//	(方案 §5.1.7 + 用户原话 2026-05-29): apps are spawned children speaking a
//	length-prefixed binary protocol via internal/apphook. So P4 = wire the
//	apphook.Hook into the request flow, NOT implement the old msgpack protocol.
//
// CRITICAL INVARIANT (方案 §6 #16): proxy MUST NOT know what business the hook
// does. It sends the raw body, gets a generic Action verdict, applies it.
//
// CRITICAL INVARIANT (方案 §6 #11): NEVER block the main LLM path. The hook's
// Detect is bounded + fail-open — on degraded/timeout it returns Allow and the
// request proceeds unmodified. A broken filter degrades to pass-through, it
// does NOT fail the user's request. (The "declared-but-no-dispatcher" case is
// handled separately by filterStub501Active at dispatch entry, which IS
// fail-loud — that's a config error, not a runtime degrade.)
//
// EXCEPTION to #11 — a child that ANSWERED with a verdict this proxy cannot read
// fails CLOSED (refused, never forwarded): an unrecognized action value
// (2026-09-13, R-compliance-canned-answer-6) and a verdict frame larger than the
// pipe's single-frame limit (TODO-120, user decision 2026-09-15, all editions).
// Neither is "the filter could not run"; forwarding on them turns a policy the
// detector applied into content that left unscanned. Timeouts and a dead child
// stay fail-open — see the FAIL-CLOSED block in applyInboundFilter.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/pipewire"
)

// pipeInputCap bounds how many bytes of a content piece the proxy sends over the
// detector pipe. It matches the detector's own NLP input cap (16KB): the
// detector only scans the first 16KB of any piece, so transferring more is pure
// waste — and a huge piece (e.g. a 180KB context) blocks the pipe long enough to
// stall the request for seconds and desync the IPC (→ the hook degrades). We cap
// the transfer and re-attach the untouched tail after masking (same forwarded
// result, fast IPC). Snapped to a rune boundary so a multibyte char never splits.
//
// 🔴 The cap is a BYTE budget, not a character budget. CJK is 3 bytes/char, so a
// Chinese prompt hits it at ~5,460 characters — roughly a third of where a reader
// who mentally translates "16KB" into "16,000 characters" would expect. Every
// derived field/metric below is therefore named `*_bytes`.
const pipeInputCap = 16 * 1024

// scanCoverage counts what compliance scanning did NOT see, so that "content was
// forwarded to the LLM unscanned" is an externally readable number instead of an
// inference from silence (health-signal-surface; bugfix 20260813-pipe-input-cap-
// truncates-silently).
//
// WHY a counter in ADDITION to the per-request WARN: the WARN is rate-limited to
// one line per request and lives in a log file that a private deployment may not
// even ship anywhere. The question an operator actually asks — "how much of my
// traffic is going unscanned in this deployment?" — needs an aggregate they can
// poll, which is /v1/diagnostics/pipeline.
//
// 🔴 GENERATION-scoped, not process-scoped, exactly like maskFidelity: the proxy
// hot-reloads in-process and these live on the *Proxy that gets replaced. Read
// them together with PipelineDiagnostics.GenerationID.
//
// Counts only — never an index, a length distribution or any content.
type scanCoverage struct {
	// truncatedPieces: how many content pieces were cut at pipeInputCap.
	truncatedPieces atomic.Int64
	// skippedBytes: total bytes that were forwarded upstream without ever being
	// handed to the detector. This is the number that quantifies the blind spot.
	skippedBytes atomic.Int64
	// incompleteScanVerdicts: how many pieces were REFUSED because the detector
	// reported that its scan did not look at everything (TODO-121). Same surface
	// and same reasoning as the counter below — it is content whose verdict was
	// produced without a complete inspection, and a rising number means either a
	// deployment under sustained load or someone probing the hit budget.
	incompleteScanVerdicts atomic.Int64
	// unreadableOversizeVerdicts: how many pieces were REFUSED because the
	// detector's verdict frame exceeded the pipe's single-frame limit (TODO-120).
	// Unlike the two counters above this is not content that went out unscanned —
	// the request was refused — but it is still content whose verdict nobody read,
	// and a rising number means legitimate large inputs are being 403'd until the
	// detector budgets its frames (TODO-120-A). Same surface, same reasoning.
	unreadableOversizeVerdicts atomic.Int64
}

// capRuneBoundary returns the largest byte offset ≤ cap on a UTF-8 rune boundary.
func capRuneBoundary(s string, limit int) int {
	if limit >= len(s) {
		return len(s)
	}
	b := limit
	for b > 0 && !utf8.RuneStart(s[b]) {
		b--
	}
	return b
}

// applyInboundFilter runs the inbound (user → LLM) compliance/filter check and
// applies the verdict. Returns true if the request should proceed to forwarding,
// false if it was blocked (caller must return without forwarding —
// applyInboundFilter has already written the error response).
//
// L1 envelope handling: the hook only ever inspects prompt CONTENT, never the
// JSON wire envelope. We parse the body, extract each content string
// (messages[].content + system, string or text-block array; see filter_content.go),
// run Detect per piece, write masked text back into the parsed structure, and
// re-serialize. So masking can never corrupt the request structure — the failure
// real Anthropic rejected with 400 before L1. Non-JSON / no-content bodies pass
// through unfiltered (fail-open; §6 #11 — a filter that can't run does NOT fail
// the user request).
//
// No-op + returns true when no hook is installed (the common default; zero
// hot-path cost behind the nil check).
//
// sessionID (resolved by the caller via resolveSessionID → the sessionid
// fingerprint table, so it works for every protocol/provider, not just Claude
// Code) serves TWO purposes here: it stamps the team audit event's session_id
// (deep-link to the conversation thread) AND it is the content cache's level-1
// isolation scope (cacheScope). Both must stay the same value — a support
// engineer correlating an audit event with cache behavior relies on it.
//
// traceID is THIS TURN's W3C trace id — the SAME value the conversation-audit
// observer stores as conversation_records.event_id (both read it off the one
// *observer.RequestContext the request built; see traceIDForAudit at the call
// site). It is the only key that joins a compliance event back to the exact
// conversation turn: the compliance event_id is minted independently inside the
// detector child (newEventID(), its own CSPRNG) and joins NOTHING. Empty when
// no observer context exists (no observers active) — then there is no
// conversation record to join to either, so an empty key is the honest answer
// rather than a freshly minted id that would join to nothing.
// (2026-08-09 F1a cross-audit key, decision A.)
// cacheableVerdict is THE single answer to "may this verdict be replayed from
// the cache instead of re-asking the detector?" — used by BOTH the read guard
// and the write guard, so the two cannot drift apart.
//
// WHY IT IS A FUNCTION AND NOT TWO INLINE CONDITIONS. Until 2026-09-13 it was
// two hand-synchronized `!= apphook.ActionBlock` comparisons with a comment on
// each pointing at the other. That survives one excluded value; the canned
// answer makes it two, and a concept with no name in the code gets re-derived by
// hand every time — which is how one side ends up excluding a verdict the other
// side still replays. (principle: documented-contract-needs-enforcement,
// 「概念在代码里没有名字就会被反复手工重推 ⇒ 先给唯一出口」.)
//
// EXCLUDED, and both for the same two reasons:
//
//   - ActionBlock (用户拍板 2026-08-08, 安全边界修复). ① A refusal must be
//     re-decided against the LATEST policy/pack every time, or an administrator
//     who relaxes a rule keeps serving stale 403s. ② It does not forward
//     upstream, so the detector call the cache would save is worth nothing —
//     the ROI is negative on its own.
//     bugfix: workflow/CI/bugfix/2026-08-08-compliance-cache-block-verdict-cached.md
//
//   - ActionAnswer (task 3.6, 2026-09-13). Both reasons carry over verbatim, and
//     design.md states the premise that makes it non-negotiable: 「代答与阻断
//     同强度」 — the canned answer is the friendly PRESENTATION of a block, not a
//     weaker outcome. clamp() already treats it as block-strength under the
//     action ceiling (TestActionCeiling_ClampsAnswerLikeBlock); the cache is the
//     other place that has to agree, or 「同强度」 is false in exactly one spot.
//     ③ A third reason is specific to 代答: the SENTENCE is administrator
//     content that can be edited in the console. A cached answer would keep
//     speaking the old sentence after the administrator replaced it — a
//     compliance statement going out in the operator's name that the operator
//     has already retracted.
//     🔴 And one concrete bug it prevents today: maskVerdict carries no
//     answer text (it holds maskedHead / reason / restorables / event). A
//     replayed Answer verdict would arrive with an empty text and degrade to a
//     403 — so an identical prompt would get a friendly 200 the first time and a
//     hard block the second, within the TTL, with nothing changed. Caching the
//     text instead was the alternative and is rejected by reasons ①–③ above.
//     围栏: TestCannedAnswer_VerdictIsNeverCached
//
// mask / warn / allow are unchanged: they forward upstream, so replaying their
// verdict saves a real detector call.
func cacheableVerdict(a apphook.Action) bool {
	return a != apphook.ActionBlock && a != apphook.ActionAnswer
}

func (p *Proxy) applyInboundFilter(
	w http.ResponseWriter,
	r *http.Request,
	model string,
	routeSource string,
	orgID string,
	virtualKeyID string,
	seatID string,
	sessionID string,
	traceID string,
	logger *slog.Logger,
) (proceed bool) {
	hook := p.filterHook
	if hook == nil {
		return true // no filter installed — pass through
	}
	// ONE org grading installation per request (TODO-188 方案 C): the supervisor
	// may hot-swap it while this request runs, and the cumulative rule and the
	// route decision below must judge this request by the same document.
	// spec: R-compliance-grading-5.1
	reqGrading := p.complianceGrading()
	if r.Body == nil {
		return true
	}
	// No body → nothing to scan → pass through QUIETLY (2026-09-03).
	//
	// net/http hands a bodiless request (GET / HEAD / OPTIONS, or a POST with
	// Content-Length: 0) to us as http.NoBody, not nil, so the nil check above
	// never fired and the request fell through to io.ReadAll → 0 bytes → JSON
	// parse failure → the WARN "no filterable content extracted; forwarded
	// UNFILTERED" (proxy.filter.skipped). That sentence means "user content
	// went upstream unmasked". For an empty request it is false — and on
	// winpc2 it was read as a P0 PII leak during triage (three team-oauth
	// group-lane requests, reason=body_not_json body_bytes=0 content_type="").
	// A diagnostic that cries wolf on empty bodies hides the day it is right.
	// Content-Length is -1 for chunked/unknown-length bodies, so a real body
	// is never mistaken for an empty one here.
	// Fence: TestApplyInboundFilter_BodilessRequestIsNotAnUnfilteredForward.
	// bugfix: workflow/CI/bugfix/2026-09-03-bodiless-request-logged-as-unfiltered-forward.md
	if r.Body == http.NoBody || r.ContentLength == 0 ||
		r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		logger.Debug("filter: request carries no body; nothing to scan",
			"event.name", observability.EventProxyFilterNoBody,
			"method", r.Method, "content_length", r.ContentLength, "route_source", routeSource)
		return true
	}

	// 🔴 PROBE EXCLUSION — the Probe pipeline is never touched by compliance.
	//
	// WHY (two independent harms, either one sufficient):
	//  1. Detection correctness. The degrade detector judges a model by the
	//     response fingerprint (chunk count / ITT rhythm) of a FIXED prompt
	//     (ai-degrade-detector shared/algorithms/rhythm.py CANONICAL_L3_PROBE).
	//     Masking rewrites that prompt, so the model answers a different question
	//     and every baseline comparison is invalid — with no symptom anywhere.
	//  2. Content attribution. A masked probe emits a compliance event. Its
	//     RouteSource is not "team", so the detector reports it on the personal
	//     lane: on Personal/Trial that lane runs in LocalIntake mode and carries
	//     the UN-REDACTED context_snippet unconditionally, which renders aikey's
	//     own probe text on the member self-view as "the content YOU sent"; on
	//     Production/Cluster the detector uploads the same event to
	//     control-master, where it lands in the administrator's audit log. Both
	//     are synthetic traffic polluting a record whose value is that every row
	//     is a real person's real prompt.
	//
	// WHY HERE and not in handleProbePipeline: this is the compliance chain's
	// entry point and its only gate. Excluding at the caller would leave the
	// exclusion to be re-derived by every future caller — which is exactly the
	// failure this fixes (serveRoute became the shared funnel for the probe/app
	// pipelines on 2026-05-23, the filter was installed in it on 2026-06-01, and
	// the spec written on 2026-06-04 recorded an exclusion that had never existed).
	//
	// SCOPE — deliberately RouteSource only, NOT the X-Aikey-Probe header. That
	// header is client-set and rides on team virtual keys, so honoring it here
	// would be a one-header DLP bypass. See isProbePipelineRoute.
	//
	// Fence: probe_pipeline_compliance_exclusion_fence_test.go.
	// Spec: workflow/CI/requirements/2026-06-04-compliance-filter-direction-and-scope.md
	if isProbePipelineRoute(routeSource) {
		logger.Debug("filter: probe-pipeline request excluded from the compliance chain",
			"event.name", observability.EventProxyFilterProbeExcluded,
			"route_source", routeSource)
		return true
	}
	filterStarted := time.Now()

	// Route class decides where the compliance event goes: team keys → master
	// (the detector returns the event and the proxy forwards it with the team
	// credential), everything else → the detector's local self-view. Only the
	// class crosses the pipe — never the credential/URL. (update doc 20260603 §3)
	routeClass := apphook.RouteClassPersonal
	if routeSource == "team" {
		routeClass = apphook.RouteClassTeam
	}
	// Team-routed events the detector hands back, uploaded to master on exit
	// (covers both the normal return and the early Block return). Async +
	// fail-loud: a dropped upload is an audit gap and must be visible.
	var teamEvents [][]byte
	defer func() {
		if routeClass != apphook.RouteClassTeam || len(teamEvents) == 0 {
			return
		}
		if p.reporter == nil {
			// Fail-loud: a team compliance event with nowhere to go is an audit
			// gap, not a silent no-op (the reporter is the only upload path).
			logger.Warn("filter: team compliance events dropped — no reporter configured",
				"event.name", "proxy.filter.compliance_upload_dropped", "count", len(teamEvents))
			return
		}
		evs := teamEvents
		// Isolated: a panic in this bypass upload must not crash the proxy. A
		// bare `go func` would escape recoverMiddleware (it only wraps ServeHTTP,
		// which has already returned by the time this async upload runs), so a
		// panic here would take down the whole process — violating bypass
		// isolation. GoSafe recovers + logs, matching every other bypass
		// goroutine in this package (stream_drainer, forward_and_resolve).
		observability.GoSafe("proxy.filter.compliance_upload", observability.Isolated, func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := p.reporter.UploadComplianceEvents(ctx, routeSource, evs); err != nil {
				logger.Warn("filter: team compliance upload failed",
					"event.name", "proxy.filter.compliance_upload_failed",
					"error", err, "count", len(evs))
			}
		})
		// LOCAL MIRROR (2026-09-03, user decision: 「团队和个人的账号都需要记录本地的
		// 合规检测，并且显示到本地 web」). A best-effort COPY of the same events to
		// this machine's self-view store, so 127.0.0.1:8090/user/compliance is
		// the machine's complete record. Reverses, for COMPLIANCE EVENTS ONLY,
		// the 2026-05-10 personal↔team isolation rule (written for usage data);
		// usage routing is untouched. Separate goroutine, separate contract:
		// never dead-lettered, and its failure never touches the master upload
		// above (see Reporter.MirrorComplianceEventsLocally). Silent no-op on a
		// host with no local store (Cluster node / server-side proxy).
		// Fence: TestApplyInboundFilter_TeamEventIsMirroredToLocalStore (RED
		// before this block: local sink timed out).
		// update: roadmap20260320/技术实现/update/20260903-合规事件团队路由本机镜像与本机页面全集显示.md
		observability.GoSafe("proxy.filter.compliance_local_mirror", observability.Isolated, func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := p.reporter.MirrorComplianceEventsLocally(ctx, routeSource, evs); err != nil {
				logger.Warn("filter: team compliance event local mirror failed (master upload unaffected)",
					"event.name", observability.EventProxyFilterComplianceLocalMirrorFailed,
					"error", err, "count", len(evs))
			}
		})
	}()
	// Personal-route request-verdict rows (TODO-87, user decision 2026-09-15 V1),
	// written on exit to this machine's LOCAL self-view store ONLY.
	//
	// 🔴 A SEPARATE BATCH FROM teamEvents, ON PURPOSE. teamEvents is the master
	// upload; putting a personal-route row there would either be dropped by the
	// route guard above or — the day that guard is loosened — reach master,
	// breaking the 2026-05-10 personal/team isolation the user kept in place.
	// This batch never holds a content row: on the personal route the detector
	// uploads those itself, and the proxy only records the request-level
	// conclusion it alone can reach. Best-effort: never dead-lettered, and a
	// failure never touches the refusal (see Reporter.UploadComplianceEventsLocally).
	// Fence: TestEscalation_PersonalRouteNoDoubleUpload.
	var localVerdictEvents [][]byte
	defer func() {
		if len(localVerdictEvents) == 0 {
			return
		}
		if p.reporter == nil {
			logger.Warn("filter: personal-route request verdict dropped — no reporter configured",
				"event.name", observability.EventProxyFilterEscalationEventDropped, "count", len(localVerdictEvents))
			return
		}
		evs := localVerdictEvents
		observability.GoSafe("proxy.filter.request_verdict_local", observability.Isolated, func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := p.reporter.UploadComplianceEventsLocally(ctx, evs); err != nil {
				logger.Warn("filter: personal-route request verdict could not be written to the local self-view "+
					"(the refusal itself is unaffected)",
					"event.name", observability.EventProxyFilterRequestVerdictLocalFailed,
					"error", err, "count", len(evs))
			}
		})
	}()

	// Read + re-buffer the body. We must restore r.Body regardless of verdict
	// so the ReverseProxy downstream can read it.
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		// Can't read body → can't inspect. Fail-open (proceed) but restore
		// whatever we got.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		logger.Warn("filter: request body read failed; proceeding unfiltered",
			"event.name", "proxy.filter.body_read_failed", "error", err)
		return true
	}

	// Extract prompt content from the wire envelope. Non-JSON or no-content
	// bodies are not something L1 can filter — forward unchanged.
	//
	// Incremental mode (form-② lobster): scan ONLY the latest user turn, not the
	// resent system + full history. extractLatestUserContent returns ok=false on
	// any shape it can't confidently reduce → we fall back to the full scan, so
	// incremental never under-scans (it only ever scans LESS when it's certain
	// the rest is unchanged history). See Proxy.filterIncremental.
	// 2026-06-16 历史漏扫修复(设计 20260616-AI合规检测-…-内容哈希缓存 §3 第一步):
	// 停用"只扫最新 user turn"的增量模式 —— 它跳过历史,用户先前说过的敏感词随历史
	// 每轮原文重发、detector 从不重扫 → 每轮透传给模型(lobster debug 实证)。
	// 改为每轮扫"全部 USER 角色消息"(extractUserContent):覆盖历史里的用户输入,
	// 但**跳过 system(admin 指令,mask 会污染 agent)和 assistant(模型返回内容,
	// 入站合规只管 user→LLM、不 mask 返回)**。只扫 user 还把片段数从"system+全历史"
	// 骤降到"用户那几条短消息",避免大 agent prompt 全量扫超时 fail-open(2026-06-16
	// 活体:扫 22 片段→9 片段超时漏 + 4.8s 延迟)。
	// AIKEY_PROXY_FILTER_INCREMENTAL_SCAN 废弃;content-hash 缓存见设计 §4(第二步)。
	//
	// 2026-08-08 P4(占位符还原方案 §3.4):"跳过 assistant"这条前提被**响应侧还原**
	// 推翻 —— 还原发生在回客户端之前,客户端历史里存的是原文,下一轮该原文以 assistant
	// 身份重发;跳过 assistant = 原文明文随历史回到上游,mask 只在首轮有效。所以扫描
	// 角色改为**可配置的 scanRoleSet(默认 user+assistant)**;system 仍不扫(mask
	// admin 指令会污染 agent)。片段数上升由 content-hash 缓存吸收 —— assistant 历史
	// 跨轮逐字不变,命中率与 user 历史同级(实测见实施计划 P4 测量记录)。
	pieces, parsed, ok := extractUserContent(bodyBytes, p.filterScanRoles)
	incremental := false // 历史漏扫修复后恒为 false(不再切到 latest-turn-only)
	if !ok || len(pieces) == 0 {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		// Link-level diagnostic (失败要显眼): a routed LLM request that yielded NO
		// filterable content was forwarded UNMASKED. Previously SILENT — the #1
		// blind spot behind "OpenClaw chat not masked but the same text via curl
		// is" (the wire bodies differ). Surface the shape so the reason is readable
		// without a rebuild. reason=body_not_json (unparseable) vs no_text_content
		// (parsed but messages[].content/system held no scannable text — e.g. the
		// text sits in a block type the extractor skips, or only tool/image blocks).
		// (2026-06-13 form-② filter-skip RCA.)
		reason := "no_text_content"
		if !ok {
			reason = "body_not_json"
		}
		logger.Warn("filter: no filterable content extracted; forwarded UNFILTERED",
			"event.name", "proxy.filter.skipped",
			"reason", reason,
			"body_bytes", len(bodyBytes),
			"content_type", r.Header.Get("content-type"),
			"top_keys", topLevelKeys(parsed),
			"messages", messageCount(parsed),
			"stream", parsed["stream"] == true)
		return true
	}

	var (
		maskedCount int
		cappedCount int // verdicts downgraded by the piece's action ceiling (方案②)
		degraded    bool
		nilResp     int // detector unreachable (pipe dead) — resp == nil
		selfDeg     int // detector returned Degraded=true (it ran but couldn't decide)
		detectNanos int64
		cacheHits   int // content-hash 缓存命中(复用判定、跳过 detector)
		cacheMiss   int // content-hash 缓存未命中(真扫 + 回填)
		// Scan-coverage accounting for pieces cut at pipeInputCap. Accumulated
		// across the loop and reported as ONE aggregated WARN after it — a large
		// agent context truncates many pieces in a single request, and a line per
		// piece would drown the signal it is meant to raise (「只记状态转变、不逐条
		// 记」). The cut itself is deliberate and unchanged; only the signal is new.
		truncPieces       int // how many pieces were cut
		truncFirstIdx     = -1
		truncTotalBytes   int // sum of the FULL size of every cut piece
		truncScannedBytes int // sum of what the detector actually received
		truncSkippedBytes int // sum of what reached the LLM unscanned (the blind spot)
		// restoreState collects numbered-placeholder → original mappings for
		// restorable masks (B3). Allocated lazily on the first restorable mask;
		// stashed on the request context for the response leg. Memory-only,
		// request-scoped, never logged/persisted (B3 拍板 2026-08-06).
		restoreState *maskRestore
		// ── Request-level escalation, step 4 of DEC-compliance-grading-11 ────
		//
		// escFindings[i] / escUnitIDs[i] belong to pieces[i]. They are allocated
		// to len(pieces) and written BY INDEX rather than appended, because
		// several branches below `continue` out of the loop and an append-based
		// collection would silently shift every later piece's findings onto the
		// wrong text — the offsets are PER-PIECE, so a shifted row does not error,
		// it slices a different substring (see Finding.StartOffset).
		//
		// Memory-only and thrown away at the end of the request: the counter's
		// whole design is that dedup happens in the proxy's memory and nothing
		// content-derived is added to any wire or row (R-compliance-grading-16).
		escFindings = make([][]Finding, len(pieces))
		escUnitIDs  = make([]string, len(pieces))
		// escEvents[i] is the RAW event document piece i came back with, kept
		// only so the canned answer's whitelisted variable can read the tenant's
		// own leaf NAME for each hit (TODO-178, R-compliance-canned-answer-10).
		// A reference, not a copy, and read on the answer path only — the
		// counter's own reader (proxy.Finding) is deliberately NOT widened,
		// because it is shared with the content-free personal-route projection
		// (see decodeEventLeafNames for the whole reason).
		escEvents = make([][]byte, len(pieces))
		// Personal-route projection accounting for this request (TODO-87): pieces
		// that came back with a count projection, and FLAGGED pieces that came back
		// without one (a detector older than this proxy). Counts only; reported
		// once after the loop by notePersonalProjectionState.
		personalProjected   int
		personalUnprojected int
		// ── Deferred refusal (DEC-compliance-grading-11 决定 5) ───────────────
		//
		// `block` / `answer` used to write their response and `return false` the
		// moment a piece produced one. They now RECORD the refusal and let the
		// loop finish, because the cumulative rule cannot count hits in pieces
		// that were never scanned. The response bytes are written after the loop
		// and stay byte-identical: FIRST refusal wins, so what the client receives
		// is the same verdict, the same status and the same body the early return
		// would have produced. The recorded events are NOT identical, by decision:
		// a refused multi-piece request records a content row for every piece
		// scanned after the refusal point (ratified 2026-09-15,
		// R-compliance-grading-15.S2, TODO-99). Fences:
		// TestEscalation_EmptyRulesKeepsOutcome (response) and
		// TestEscalation_ZeroRulesRefusedMultiPieceRecordsEveryScannedPiece (rows).
		//
		// 🔴 refusalMsg is assigned ONLY from resp.Reason or from a string
		// literal, and that is load bearing: the red-line fence
		// TestFence_GuardrailShortCircuitBodyIsNeverInterpolated proves the body
		// handed to the client is verbatim by following a local's assignments, and
		// resp.Reason is the expression its exemption table names. Assigning it
		// through any other expression re-opens an approved red-line exemption
		// under a new name.
		refusalAction   = apphook.ActionAllow // ActionAllow = nothing refused yet
		refusalMsg      string
		refusalAnswer   *cannedAnswerPlan
		refusalDegraded bool
		// refusalByRoutePolicy: the refusal was decided by the grading route
		// policy (R-compliance-grading-8), which answers with its OWN code —
		// COMPLIANCE_ROUTE_POLICY_DENIED means "not HERE", COMPLIANCE_BLOCKED means
		// "not anywhere", and the user's remedy differs.
		refusalByRoutePolicy bool
	)
	// Record every filterable request, including block/degraded early returns.
	// A request with at least one cache hit is the steady-state incremental lane;
	// zero hits is the cold lane. The metric is whole-filter wall time, so JSON
	// parsing, hashing, IPC and policy application are all represented.
	defer func() {
		p.filterPerformance.observe(time.Since(filterStarted), cacheHits > 0)
	}()

	// content-hash 缓存(设计 §4):仅当缓存启用时才算 scope/detectorVer/contentVer。
	// 缓存关闭(cache == nil)时下面循环根本不碰 hash → 不付 content-hash 代价(INV-6)。
	// scope = 隔离桶(同会话历史复用、跨会话不串);detectorVer 让 detector 重启自动失效
	// 旧条目;contentVer 让 detector 原地热切 ruleset(管理员增删规则)也自动失效 —— 三者
	// 都进 key,见 cacheKey。
	// scope 复用调用方已解析的 sessionID(serveRoute → resolveSessionID → sessionid
	// fingerprint 表):Claude 专有 header 之外的 provider(kimi/codex/cursor/cline …)
	// 现在也能拿到会话级隔离桶,不再降级到 vk/global 让多会话共桶。见 cacheScope 注释。
	//
	// `cache` shadows p.filterCache for the rest of this request so that "cache is
	// unusable" has ONE representation. FAIL-SAFE, NOT FAIL-STALE (2026-08-13): if
	// the hook declares a hot-swappable content set but cannot currently say which
	// one is live (child unreachable / first poll not back), we scan every piece
	// for real rather than replay verdicts that may have been minted under a
	// ruleset the admin has since deleted. 宁可多扫,不可用陈旧规则.
	cache := p.filterCache
	// 审计单元作用域(2026-09-08):与缓存桶用同一个 scope,但**无条件计算** —— 审计
	// 去重的正确性绝不能寄生在"缓存开没开"上。cache==nil(未装)或 SUSPENDED(detector
	// 说不清自己的规则集)时,每片都会真扫,而真扫正是重复审计行的来源,所以恰恰是这两
	// 种情况下最需要去重键。见 auditUnitID 的不变量注释。
	auditScopeKey := cacheScope(sessionID, parsed, virtualKeyID)
	var detectorVer, contentVer string
	if cache != nil {
		epoch, cacheable := apphook.CacheEpoch(hook)
		// Transition-only observability for the fail-safe branch (2026-08-13,
		// review finding B6). The BEHAVIOR is unchanged and deliberate; what was
		// missing is that switching the cache off is a silent, permanent latency
		// regression for a node whose detector is too old to answer op=ListPacks.
		// See noteVerdictCacheState for why this is latched rather than per-request.
		p.noteVerdictCacheState(logger, hook, cacheable)
		if !cacheable {
			cache = nil // both the read and the write below are skipped
		} else {
			detectorVer = hook.Status().Version
			contentVer = epoch
		}
	}

	for i := range pieces {
		// Cap the per-piece payload sent over the pipe (the detector only scans
		// the first pipeInputCap bytes anyway). The untouched tail is re-attached
		// after masking below, so the forwarded prompt is identical to sending the
		// whole piece — but a huge piece can't stall/desync the IPC.
		head := pieces[i].text
		var tail string
		if len(head) > pipeInputCap {
			b := capRuneBoundary(pieces[i].text, pipeInputCap)
			head, tail = pieces[i].text[:b], pieces[i].text[b:]
			// Record the blind spot (2026-08-13). `tail` is spliced back verbatim
			// after masking and forwarded to the LLM having NEVER been inspected:
			// a secret sitting at byte 16385 of this piece is invisible to every
			// downstream surface — no mask, no compliance event, no audit trail.
			// The measured behavior was 8 findings with the key at 15 KB and 0
			// findings with the same key at 16 KB, with nothing in between to say
			// why. Keeping the cut (correct) while emitting nothing (wrong) is the
			// whole bug; these four counters are the fix.
			truncPieces++
			if truncFirstIdx < 0 {
				truncFirstIdx = i
			}
			truncTotalBytes += len(pieces[i].text)
			truncScannedBytes += len(head)
			truncSkippedBytes += len(tail)
		}
		// content-hash 缓存:历史里逐字未变的内容(每轮重发)命中缓存即复用判定、
		// 跳过 detector IPC;只有新增/被改写(miss)才真扫。命中时合成一个等价 resp,
		// 走下面同一套处理(mask/allow/...)。缓存关闭/不可用(cache==nil)则直接真扫。
		// 内容身份:**无条件计算**(sha256 于 16KB ≈ 8µs,相对 detector 的毫秒级可忽略;
		// 设计文档 §4.1 实测 hash 合计 0.18ms vs detect 4822ms)。它同时是两件事的判据:
		//   ① 缓存命中判据(这段内容扫过没有)
		//   ② 审计单元去重键(这段内容记过账没有)
		// 两者必须同源 —— 分家就是 2026-06-17~2026-09-08 那个 BUG 的全部根因。
		// 见 auditUnitID 的不变量注释。
		contentID := hashHead(head)
		var resp *apphook.Response
		var ckey string
		if cache != nil {
			ckey = cacheKey(detectorVer, contentVer, contentID) // level-2 key (scope is separate)
			// 读侧 block 守卫(用户拍板 2026-08-08,与写侧不入缓存配套):即便缓存里
			// 残留了历史 block verdict(理论上写侧已不再写入;此处兜底进程内 pre-fix
			// 污染 + 防写侧未来回归),也当作 miss、落到下方真扫按最新策略重判 —— block
			// 是安全决策不复用陈旧拒绝。仅精确排除 ActionBlock,mask/warn/allow 命中路径
			// 逐字不变(它们 action != ActionBlock,条件恒真)。
			// v.action.Recognized() 是 fail-closed 的读侧配套(2026-09-13,
			// R-compliance-canned-answer-6):写侧已不再写入无法识别的判定(见下方
			// Detect 后的归一),此处兜底进程内 pre-fix 污染 —— 回放一个本 build 读不懂
			// 的判定没有任何意义,当 miss 落到真扫按最新策略重判。
			if v, ok := cache.Get(auditScopeKey, ckey); ok && v.action.Recognized() && cacheableVerdict(v.action) {
				// Restorables replay from cache (offsets only): the hash-matched head
				// is byte-identical, so the same spans slice the same originals.
				// Event replays too (2026-08-08 审计缺口修复): a flagged piece resent
				// every turn keeps producing its audit event instead of going silent
				// after the first scan, and the detector's event_id makes the repeat
				// idempotent at both ingest paths — see maskVerdict.event for why this
				// reconciles a failed upload without double-counting a successful one.
				resp = &apphook.Response{Action: v.action, MutatedPayload: []byte(v.maskedHead), Reason: v.reason, Restorables: v.restorables, Event: v.event}
				cacheHits++
			}
		}
		if resp == nil { // 缓存 miss 或缓存关闭/不可用 → 真扫
			if cache != nil {
				cacheMiss++
			}
			_t0 := time.Now()
			resp = hook.Detect(r.Context(), &apphook.Request{
				Direction:   apphook.DirectionInbound,
				Payload:     []byte(head),
				TargetModel: model,
				RouteClass:  routeClass,
				// RequestID best-effort from the inbound trace header; child uses it
				// only for log correlation. Empty is fine.
				RequestID: r.Header.Get("x-request-id"),
				// UserRole left empty for MVP — PoC uses default-tenant pack
				// (方案 §5.4.5: PoC 期 child 忽略 user_role, 统一用 default).
			})
			detectNanos += time.Since(_t0).Nanoseconds()
			// ── FAIL-CLOSED ON AN UNREADABLE VERDICT ────────────────────────────
			// spec (PROPOSAL layer, 需求包 roadmap20260320/技术实现/阶段9-商业化版本/
			// 博时基金合规能力融合/openspec/changes/add-compliance-grading-fusion/
			// specs/compliance-canned-answer/spec.md):
			//   R-compliance-canned-answer-6    未识别动作 SHALL 按 ActionBlock 处理
			//   R-compliance-canned-answer-6.S1 403 COMPLIANCE_BLOCKED，上游 0 请求
			//
			// 🔴 2026-09-13 REVERSAL — read before "restoring" the old behavior.
			// This used to be handled by the switch's `default:` below as a LOUD
			// FAIL-OPEN (2026-06-22 review). The "loud" half is kept verbatim; the
			// "open" half is reversed, because two opposite failures were conflated:
			//
			//   child could not ANSWER (timeout/crash/not installed) → fail-OPEN,
			//     §6 #11. Those paths return an explicit ActionAllow+Degraded from
			//     ChildHook.Detect, are Recognized(), and are untouched here.
			//   child ANSWERED with a verdict we cannot read → fail-CLOSED. The
			//     action value is policy the master handed down; not recognizing it
			//     means this proxy is older than the policy or the policy was
			//     tampered with. Neither is a reason to forward the content.
			//
			// Placed HERE, before the cache write, on purpose: an unreadable verdict
			// normalizes to Block and Block is never cached (see the guard below), so
			// the cache cannot come to hold a value no reader can interpret.
			//
			// Reason is cleared: on a real Block it is empty by construction and the
			// client gets the constant refusal (see guardrailVerbatimSources in
			// compliance_guardrail_response_fence_test.go). On THIS path it is a
			// string of unknown provenance from a verdict we just decided we cannot
			// read — it must not be echoed to the caller.
			// 围栏: TestApplyInboundFilter_UnknownAction_FailsClosedBlocked ·
			//       internal/apphook TestUnknownAction_TreatedAsBlock
			//
			// SECOND SHAPE, same branch (TODO-120, P0, user decision 2026-09-15 P2:
			// every edition): the child answered but its verdict FRAME exceeded the
			// pipe's single-frame limit, so the frame was skipped unread
			// (resp.VerdictUnreadable, set by ChildHook). Until then it was reported
			// as Degraded and fell through to the fail-open `case ActionAllow` below —
			// repeating a sensitive value a few hundred times forwarded it unscanned.
			// It is refused here with the constant message (Reason cleared: the
			// rule above about not echoing an unreadable verdict applies verbatim),
			// and Block is never cached (cacheableVerdict), so no replay either.
			// Known cost: no team audit event for this piece — the frame that held
			// it was never read. The request is refused, so no content left.
			// 围栏: TestApplyInboundFilter_LiveDetector_OversizeVerdictNeverForwardedUnscanned ·
			//       TestApplyInboundFilter_OversizeVerdictFailsClosedAndIsCounted ·
			//       internal/apphook TestChildHook_OversizeFrameFailsClosedAndStreamStaysInSync
			switch {
			case resp == nil:
			case resp.VerdictUnreadable:
				p.scanCoverage.unreadableOversizeVerdicts.Add(1)
				logger.Warn("filter: detector verdict frame exceeded the pipe frame limit and was not read; "+
					"refusing the request (fail-CLOSED)",
					"event.name", observability.EventProxyFilterVerdictUnreadableOversize,
					"hook", hook.Name(), "frame_bytes", resp.UnreadableFrameBytes,
					"max_bytes", pipewire.MaxPayloadBytes)
				resp.Action = apphook.ActionBlock
				resp.Reason = ""
			case resp.ScanIncomplete:
				// THIRD SHAPE of the same family (TODO-121, P0, user decision
				// 2026-09-15: every edition). The child answered, and its answer says
				// it did not finish looking — a lane hit its hit budget or overran
				// its deadline. Forwarding on that is how a prompt engineered to
				// explode the hit count reached the upstream uninspected, so it is
				// refused with the same constant message and the same Reason-clearing
				// rule as the two branches around it. Block is never cached, so there
				// is no replay either.
				//
				// A TIMEOUT of the whole Detect stays fail-OPEN next door (Degraded →
				// case ActionAllow): that is "the child could not answer", §6 #11, and
				// reversing it is NOT part of this change.
				// 围栏: TestApplyInboundFilter_IncompleteVerdictFailsClosed ·
				//       TestApplyInboundFilter_DegradedFailsOpen (unchanged control)
				p.scanCoverage.incompleteScanVerdicts.Add(1)
				logger.Warn("filter: detector reported an INCOMPLETE scan for this content; "+
					"refusing the request (fail-CLOSED)",
					"event.name", observability.EventProxyFilterScanIncomplete,
					"hook", hook.Name())
				resp.Action = apphook.ActionBlock
				resp.Reason = ""
			case !resp.Action.Recognized():
				logger.Warn("filter: unrecognized apphook action; refusing the request (fail-CLOSED)",
					"event.name", "proxy.filter.unknown_action",
					"action", int(resp.Action), "reason", resp.Reason, "degraded", resp.Degraded)
				resp.Action = apphook.NormalizeAction(resp.Action)
				resp.Reason = ""
			}
			// 只缓存"确定性"判定:degraded(超时/fail-open)与 nil 不缓存,否则会把
			// "没扫成"误记成 allow、下轮命中缓存就放行(违反 INV-2)。
			//
			// BLOCK 不入缓存(用户拍板 2026-08-08,安全边界修复):block(ActionBlock)是
			// 安全关键决策,每次都必须按【最新策略/pack】重新走 detector 判定,绝不复用
			// 缓存的陈旧拒绝。WHY:①缓存命中回放不调 detector(见上方 Get 分支),若把 block
			// 入缓存,则管理员放宽策略后陈旧 block 仍会持续 403;②block 走拒绝路径不转发
			// 上游,缓存省下的那一次 detector 调用收益可忽略,ROI 为负。
			// 2026-08-13 起 in-place pack swap 已由 contentVer 进 key 自动失效(见 cacheKey),
			// 所以①里"放宽后无法立即生效"的窗口已从"近乎永久"收敛到一个 poll 周期 —— 但这条
			// 规则**不因此放宽**:contentVer 只覆盖 detector 自报的 pack 集合,而 block 还受
			// 请求级/策略级因素影响,且它的缓存收益本来就是负的(理由②独立成立)。
			// mask/warn/allow 缓存行为保持不变(它们转发上游,复用判定收益实在)。
			// 隐患溯源:CN_ADDRESS 本身无 block 档,但其他 entity 的 HighRiskBlock
			// (policy.go HighRiskBlock)已在用这条链 → 当前生产就有此隐患。
			// 配套读侧守卫见上方 Get 分支 —— 两侧现在都过同一个 cacheableVerdict(),
			// 见该函数的注释:第三个取值(代答)加进来时,「写侧排除 / 读侧守卫」这对
			// 手工同步的条件就该收成一个出口了。
			// !resp.ScanIncomplete is redundant TODAY — the branch above rewrites an
			// incomplete verdict to Block and cacheableVerdict already excludes
			// Block — and it is written anyway, because the thing this guard has to
			// survive is a future edit that moves or softens that rewrite. A verdict
			// produced from a scan that did not finish must never be replayed for an
			// hour, and that rule should be legible HERE, at the write, rather than
			// depending on a chain of reasoning through another branch (TODO-121).
			if cache != nil && resp != nil && !resp.Degraded && !resp.ScanIncomplete && cacheableVerdict(resp.Action) {
				// maskedHead is cached in the detector's NUMBERLESS token form —
				// per-request numbering happens AFTER cache replay so numbers stay
				// request-scoped (同请求内按出现顺序编号) instead of leaking a stale
				// numbering across turns.
				// event: cached so a cache HIT can re-emit the same audit event (see
				// maskVerdict.event). Stored as handed over — never mutated in place
				// (injectTenant/VirtualKey/Seat/Session all return fresh slices), so the
				// async uploader and the cache can share the bytes read-only.
				cache.Put(auditScopeKey, ckey, maskVerdict{
					action:      resp.Action,
					maskedHead:  string(resp.MutatedPayload),
					reason:      resp.Reason,
					restorables: resp.Restorables,
					event:       resp.Event,
				})
			}
		}
		if resp == nil { // defensive: a nil response is treated as degraded allow
			degraded = true
			nilResp++
			continue
		}

		// Feed the request-level counter. Decoded from what the detector handed
		// back for THIS piece — including on a cache hit, whose replayed bytes are
		// the same document (R-compliance-grading-18.S3 requires exactly that: a
		// history piece served from cache still participates in this turn's
		// count). On a team route that is the full event; on a personal route it
		// is the content-free count projection (TODO-87, 2026-09-15: the org's
		// cumulative rule follows the PERSON). ONE reader for both routes, so the
		// two cannot count differently — see decodeEventFindings.
		// spec: R-compliance-grading-15
		escFindings[i] = decodeEventFindings(resp.Event)
		escEvents[i] = resp.Event
		if routeClass != apphook.RouteClassTeam {
			// The proxy uploads nothing on this route, so the only id that names
			// this piece's content row is the one the detector uploaded it under.
			// The team branch below mints its own content-derived id instead,
			// because there the proxy IS the uploader.
			escUnitIDs[i] = decodeEventID(resp.Event)
			switch {
			case len(resp.Event) > 0:
				personalProjected++
			case resp.Action != apphook.ActionAllow:
				// Flagged but uncountable: the detector predates TODO-87.
				personalUnprojected++
			}
		}

		// ── ACTION CEILING (方案② 2026-08-10) ────────────────────────────────
		// The piece's ceiling comes from the SAME table row that made its block
		// type scannable at all (blockScanPolicy, filter_content.go). Tool blocks
		// are scanned so their findings are RECORDED, and capped so the 216
		// gitleaks-derived `block` rules can never fire on an agent's file reads.
		// Everything else keeps ceilingFull, i.e. byte-identical behavior.
		//
		// 🔴 The clamp is applied HERE, after the cache, on purpose: the cache
		// stores the detector's RAW verdict keyed on content, and the ceiling is a
		// property of the PIECE, not of the text. The same string appearing once in
		// prose and once in a tool_result must mask in the first place and only
		// audit in the second — which only works if the cached value is uncapped
		// and the cap is re-applied per piece.
		action, capped := pieces[i].ceiling.clamp(resp.Action)
		if capped {
			cappedCount++
			// 失败要显眼 (inverted): this is the one line that says "we found
			// something in a tool payload and deliberately let it through". Counts
			// and the verdict name only — never content.
			logger.Info("filter: verdict capped to audit by block-type ceiling; content forwarded UNCHANGED",
				"event.name", observability.EventProxyFilterActionCapped,
				"detector_action", resp.Action.String(), "ceiling", pieces[i].ceiling.String())
		}

		// Team-routed only: collect the event the detector handed back for the
		// proxy to forward to master (the deferred upload sends them). Guard on
		// routeClass so the proxy stays self-consistent even if a child ever
		// returned an Event on a personal route — those must never be uploaded.
		// The proxy stamps the authoritative tenant_id = the VK's resolved org
		// (NOT user input): the detector runs on a client with no org context,
		// and the master must not trust a client-self-reported tenant.
		// (update doc 20260603 §2.1)
		//
		// Cache hits contribute here too (2026-08-08): the batch now carries one event
		// per FLAGGED piece in the request, not just per freshly-scanned piece. Bounded
		// by the request's user-message count (the same bound the scan loop pays), and a
		// batch is capped at 2 MiB server-side (maxIntakeBody) ≈ thousands of events, so
		// a realistic conversation stays orders of magnitude under it.
		// Index of THIS piece's event in teamEvents, or -1 when the piece produced
		// none. The Mask branch below uses it to backfill wire_label after the
		// labels are allocated. WHY an index instead of moving the append below the
		// switch: several branches `continue` out, and moving the append past them
		// would silently drop audit events for exactly the pieces that most need
		// one (an unwritable piece, an empty mask payload).
		teamEventIdx := -1
		if routeClass == apphook.RouteClassTeam && len(resp.Event) > 0 {
			// Stamp BOTH authoritative attribution fields the proxy resolved (the
			// detector has neither): tenant_id = the VK's org, virtual_key_id = the
			// VK itself (per-seat attribution at a centralized gateway). The VK never
			// crosses the detector pipe. See 20260611 集中化网关归因改造.
			// seat_id: the org seat of the human (route.SeatID, same field usage
			// + conversation audit carry). Without it the master compliance-audit
			// page — which resolves the seat alias/email from seat_id — falls back
			// to the raw detector user_id (metadata.user_id, a Claude/session id),
			// so pool-VK events showed a stranger id instead of the employee's
			// alias (2026-07-08, mirrors the conversation-audit seat fix).
			// session_id: the conversation session (resolveSessionID, the SAME
			// source the conversation-audit observer uses), so the compliance
			// audit drawer can open the conversation THREAD this flagged prompt
			// belongs to (2026-07-08 cross-audit link, decision 2a).
			//
			// trace_id: THIS TURN's trace id — the key that joins to the single
			// conversation_records row for this turn.
			//
			// 🔴 Correction (2026-08-09, F1a): the comment that used to sit here
			// claimed "event_id joins the turn". It never did. The compliance
			// event_id is generated inside the detector CHILD PROCESS by its own
			// newEventID() CSPRNG (cmd/detector/main.go), while a conversation
			// turn's event_id is the proxy's W3C trace id. Two unrelated id
			// spaces — so the audit page's `?event=` deep link, added 2026-07-08
			// on the strength of that wrong comment, has been dead code that
			// matched nothing ever since. trace_id is the real join key, and it
			// is stamped HERE (per-piece loop) so all N events a single turn
			// produces carry the SAME value → N:1 events-to-turn.
			//
			// action_taken: rewritten to the CAPPED verdict when the ceiling
			// downgraded it. The detector decided "mask"; the proxy did not mask.
			// Leaving the detector's word in the record would tell the compliance
			// dashboard the content was redacted when it went out verbatim — a
			// false-safety signal, which is the exact failure mode this whole area
			// keeps producing. The event still exists (that is the point of 方案②);
			// only its verdict is corrected to what actually happened.
			ev := injectTraceID(injectSession(injectSeat(injectVirtualKey(injectTenant(resp.Event, orgID), virtualKeyID), seatID), sessionID), traceID)
			// event_id 改写为内容派生的审计单元 id(用户拍板 2026-09-08,反转 2026-08-08
			// 「event_id 归 detector 所有,proxy 无权铸造」条款)。原条款的理由是"不得虚构
			// detector 的身份";这里不是虚构,是从 detector 判定的**那段内容**确定性派生,
			// 语义不同。反转的必要性:detector 的 CSPRNG id 让"同一段内容重扫一次"= 一条
			// 新审计行,而两条入库路径的 ON CONFLICT (event_id) 只能吸收重放、吸收不了重扫。
			// spec: R-compliance-filter-scope-2(审计单元 = 一个会话内的一段违规内容)
			// bugfix: workflow/CI/bugfix/2026-09-08-compliance-audit-unit-id-parasitic-on-cache.md
			unitID := auditUnitID(auditScopeKey, contentID)
			// Remember it for the request verdict: R-compliance-grading-18 says
			// the verdict row SHALL list the content rows that were counted, and
			// SHALL relate to them through that list rather than through
			// trace_id — a history piece served from cache keeps the trace it was
			// first stored with, so a trace join would silently miss exactly the
			// rows the cumulative rule needed.
			escUnitIDs[i] = unitID
			ev = injectEventID(ev, unitID)
			if capped {
				ev = injectActionTaken(ev, pieces[i].ceiling.String())
			}
			teamEvents = append(teamEvents, ev)
			teamEventIdx = len(teamEvents) - 1
		}

		// 代答 (canned answer): decide ONCE, here, whether this verdict can
		// actually be served — and degrade to Block if it cannot.
		//
		// 🔴 WHY THE DECISION IS HERE AND NOT IN THE SWITCH BRANCH. By the time
		// the branch runs, the response writer is the only thing left; a
		// discovery at that point ("no text after all") has nowhere to go but a
		// half-written body. Resolving first means the `case ActionAnswer` below
		// is reached ONLY when a complete answer is guaranteed, and every other
		// outcome takes the ordinary, well-tested block path with no second
		// refusal implementation to keep in sync.
		//
		// 🔴 AND WHY THE GUARD MUST LIVE IN THIS REPOSITORY AT ALL. master
		// stopped rejecting an out-of-domain answer_source on 2026-09-12 (task
		// 1.20: 200 + NULL column + WARN, no longer 400), so nothing downstream
		// reports it if the proxy answers with nothing. R-compliance-canned-
		// answer-2.S2 「三级皆空 → 退回阻断而非放行」 is held here or nowhere.
		// Fence: TestCannedAnswer_EmptyTextFallsBackToBlock.
		var cannedAnswer *cannedAnswerPlan
		if action == apphook.ActionAnswer {
			cannedAnswer = planCannedAnswer(resp, r, bodyBytes, logger)
			if cannedAnswer == nil {
				action = apphook.ActionBlock
			}
		}
		if teamEventIdx >= 0 && action == apphook.ActionAnswer && cannedAnswer.source != "" {
			// answer_source travels with the audit event so an administrator can
			// tell whether the sentence the user saw came from the rule they just
			// edited or from the org-wide default they forgot about (design §4b,
			// R-compliance-canned-answer-7). `none` never reaches here — that case
			// degraded to Block above and is recorded as one, below.
			teamEvents[teamEventIdx] = injectAnswerSource(teamEvents[teamEventIdx], cannedAnswer.source)
		}
		if teamEventIdx >= 0 && resp.Action == apphook.ActionAnswer && action == apphook.ActionBlock {
			// The detector said "answer"; the proxy blocked. Correct the record to
			// what ACTUALLY happened, exactly as the ceiling-capped case does a few
			// lines up — leaving the detector's word in would tell the compliance
			// dashboard the user got a friendly refusal when they got a 403.
			teamEvents[teamEventIdx] = injectActionTaken(teamEvents[teamEventIdx], apphook.ActionBlock.String())
		}

		switch action {
		case apphook.ActionBlock:
			// Refuse the whole request — one content piece contained content the
			// policy blocks (e.g. full private key, batch customer data). Restore
			// the original body for any error-path logging; do NOT forward.
			//
			// 🔴 THIS IS THE GUARDRAIL SHORT-CIRCUIT. Two red lines govern the
			// bytes written below, and the canned answer (代答) is specified to
			// land at this exact point rather than beside it:
			//
			// R-compliance-canned-answer-1 代答短路请求，原文不出上游
			//   —— 与 ActionBlock 使用同一短路点与同一 `return false` 语义。
			//   Its 射程 note carries design §6 不变量 13: 护栏只在「请求未发往
			//   上游」时写响应体；一旦转发过上游，响应体永不由护栏改写（占位符
			//   还原是既有且唯一的例外，见 filter_restore.go）。
			// R-compliance-canned-answer-3 代答文案原样输出，不得插值命中片段
			//   —— design §6 不变量 12. Whatever text goes to the client here is
			//   printed VERBATIM: no Sprintf, no template, no concatenation of
			//   anything the detector found. Interpolation would turn the refusal
			//   into a channel that echoes the customer's ID-card number back to
			//   whoever sent it — the same red line as 「原文不出客户信任边界」,
			//   reached from the other side.
			//
			// bugfix: 需求包 roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
			//   openspec/changes/add-compliance-grading-fusion/specs/compliance-canned-answer/spec.md
			//   (both rules are still PROPOSAL-layer, so they are referenced by id
			//   rather than written as `spec:` anchors — a `spec:` anchor tells
			//   check-spec-writeback the rule has landed, and the canned answer has
			//   not. Upgrade both in the change that lands it. Same convention as
			//   aikey-control-master internal/compliance/grading_document.go.)
			// 围栏: compliance_guardrail_response_fence_test.go —
			//   TestFence_GuardrailShortCircuitBodyIsNeverInterpolated derives THIS
			//   call site from the source and rejects any non-verbatim argument, so
			//   the canned answer inherits the check without anyone updating a list.
			//
			// 🔴 2026-09-14 (task 3.11, DEC-compliance-grading-11 决定 5): the
			// SHORT-CIRCUIT IS UNCHANGED — nothing is forwarded, the request never
			// becomes an upstream request — but the RESPONSE WRITE moved to just
			// after this loop, so the cumulative rule can see the pieces that come
			// after this one. First refusal wins, so the bytes the client receives
			// are the same ones this branch used to write.
			if refusalAction == apphook.ActionAllow {
				refusalAction = apphook.ActionBlock
				// Assigned from resp.Reason ONLY — see the refusalMsg declaration
				// for why the fence depends on that. The empty-reason fallback
				// stays at the WRITE site, so the "filter: request blocked" log
				// keeps reporting the detector's raw reason (empty when it gave
				// none) exactly as it did before the write moved.
				refusalMsg = resp.Reason
				refusalDegraded = resp.Degraded
			}

		case apphook.ActionAnswer:
			// 代答 — the SAME short-circuit as ActionBlock and the same
			// `return false`; only the bytes differ. Deliberately a sibling case
			// rather than a variant inside the block branch, because Go cannot
			// fall through backwards and because the two write different status
			// codes: this is the one place in the guardrail that answers 200.
			//
			// spec (PROPOSAL layer, 需求包 roadmap20260320/技术实现/阶段9-商业化版本/
			// 博时基金合规能力融合/openspec/changes/add-compliance-grading-fusion/
			// specs/compliance-canned-answer/spec.md):
			//   R-compliance-canned-answer-1  代答短路请求，原文不出上游 —— nothing
			//     was forwarded before this point and nothing is after it; the
			//     request never becomes an upstream request at all.
			//   R-compliance-canned-answer-3  代答文案原样输出，不得插值命中片段 ——
			//     cannedAnswer.text goes to writeCannedAnswer untouched. No
			//     Sprintf, no template, no concatenation with anything the
			//     detector found. See canned_answer.go's red line 1 for what
			//     interpolation here would actually mean.
			//
			// 🔴 NOT counted in p.errors, unlike the block above, and that is a
			// judgement worth writing down: a canned answer is a SUCCESSFUL
			// refusal — HTTP 200, the client's SDK parses it, the user reads a
			// sentence. Counting it as a proxy error would make an organization
			// that configured 代答 look unhealthy in proportion to how well the
			// feature is working. The compliance event (already appended above)
			// is where a refusal is counted.
			//
			// 🔴 2026-09-14 (task 3.11): like the block above, the WRITE moved to
			// just after the loop; the short-circuit itself is untouched. THE PLAN
			// IS CARRIED OVER WHOLE — the sentence the client reads is the one
			// THIS piece resolved, not a later piece's, because first refusal
			// wins.
			if refusalAction == apphook.ActionAllow {
				refusalAction = apphook.ActionAnswer
				refusalAnswer = cannedAnswer
				refusalDegraded = resp.Degraded
			}

		case apphook.ActionMask:
			if pieces[i].setText == nil {
				// Defensive: a piece with no write-back target reached a Mask verdict.
				// Structurally unreachable — the only unwritable piece (the joined
				// tool_use.input blob) is pinned to an audit ceiling that clamps Mask
				// away above. If this fires, someone raised that ceiling without
				// splitting the join, and the correct outcome is "forward unchanged +
				// say so loudly", never a silent partial mask.
				logger.Warn("filter: Mask verdict on a piece with no write-back target; content forwarded UNCHANGED",
					"event.name", observability.EventProxyFilterMaskUnwritablePiece,
					"ceiling", pieces[i].ceiling.String())
				continue
			}
			m := resp.MutatedPayload
			if len(m) == 0 {
				// Mask verdict but no payload — leave this piece unchanged.
				logger.Warn("filter: Mask verdict with empty MutatedPayload; leaving content unchanged",
					"event.name", "proxy.filter.mask_empty")
				continue
			}
			masked := string(m)
			// B3 restorable masks: renumber the detector's numberless token into
			// per-request labels ({{ADDR_N}}) and record label→original in
			// the request's restore state (consumed by the response leg). Runs for
			// both fresh Detects and cache replays (numbering is request-scoped).
			// Zero cost when the mask carries no restorables (the usual case).
			var spanLabels map[[2]int]string
			if len(resp.Restorables) > 0 {
				if restoreState == nil {
					restoreState = newMaskRestore()
					// Hand the state the process-wide fidelity counters so the
					// request leg's "issued" and the response leg's "restored"
					// land in ONE place without a per-request lifecycle hook
					// (方案 §3.2 L3 保真率指标). Counts only.
					restoreState.fid = &p.maskFidelity
				}
				masked, spanLabels = renumberRestorables(head, masked, resp.Restorables, restoreState, logger)
			}
			// Masked head (the scanned first pipeInputCap bytes) + the untouched
			// tail (forwarded raw, never scanned — same as the detector's own cap).
			pieces[i].setText(masked + tail)
			maskedCount++
			// Backfill the labels this piece just issued onto this piece's event, so
			// the audit trail records what was actually SENT ({{PHONE_1}}) next to
			// the detector's numberless snippet ({{PHONE}}). Done here, after the
			// substitution, because the labels do not exist until now — and scoped to
			// THIS piece, because the offsets are relative to this piece's head
			// (方案 L §16.3). Cache replays pass through here identically: the numbers
			// are re-allocated per request after replay, so the backfilled label is
			// this request's, never a stale one from the turn that populated the
			// cache entry.
			if teamEventIdx >= 0 && len(spanLabels) > 0 {
				teamEvents[teamEventIdx] = injectWireLabels(teamEvents[teamEventIdx], spanLabels)
			}

		case apphook.ActionWarn:
			logger.Info("filter: content warned (passed through)",
				"event.name", "proxy.filter.warned", "reason", resp.Reason)

		case apphook.ActionAllow: // incl. degraded fail-open
			if resp.Degraded {
				degraded = true
				selfDeg++
			}

		default:
			// UNREACHABLE by construction: every verdict was passed through
			// apphook.NormalizeAction above (unrecognized → Block), and
			// ActionAnswer was degraded to Block just before this switch while
			// SupportsCannedAnswer() is false. Kept, and kept fail-CLOSED, because
			// the thing this branch has to survive is a FUTURE edit that removes or
			// bypasses the normalization — the 2026-06-22 review was exactly that
			// (an exhaustive-switch refactor dropped the catch-all). A refusal is
			// the only outcome here that cannot silently forward content unscanned.
			// Duplicates the refusal rather than reusing the ActionBlock branch:
			// the two are reached for different reasons and neither may `fallthrough`
			// into an earlier case in Go.
			//
			// The ERROR stays HERE, at the point of detection, because it names
			// THIS piece's unreadable action; only the response write moved after
			// the loop with the other two refusals (task 3.11). The message it
			// refuses with is the constant, exactly as before.
			logger.Error("filter: verdict reached the dispatch switch un-normalized; refusing (fail-CLOSED)",
				"event.name", "proxy.filter.unknown_action",
				"action", int(action), "raw_action", int(resp.Action))
			if refusalAction == apphook.ActionAllow {
				refusalAction = apphook.ActionBlock
				refusalMsg = "request blocked by compliance policy"
			}
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// REQUEST-LEVEL VERDICT — step 4 of DEC-compliance-grading-11.
	//
	// The detector decides per CONTENT PIECE and is stateless per frame, so a
	// request whose three messages carry one customer record each looks like
	// three separate single-hit prompts to it. The cumulative rule («≥L4 命中
	// ≥3 条 → 拦截») is a statement about the REQUEST, and this — after the loop,
	// holding every piece's findings — is the only place in the system where the
	// request as a whole exists (DEC-compliance-grading-11 决定 1).
	//
	// 🔴 IT RUNS ON EVERY FILTERABLE REQUEST, including ones with no rules
	// configured and ones already refused above. Making it conditional on
	// len(rules) > 0 would be free and is exactly what R-compliance-grading-15.S2
	// rules out — 「不接受『没配就走不到』作为等价性论据」: an unconfigured org must
	// exercise the same path, so the counters below can prove it ran and
	// concluded nothing.
	//
	// spec: R-compliance-grading-15 — proposal-layer, hence `rule:` and not a
	// `spec:` anchor (see the canned-answer branches above for the convention).
	// rule: R-compliance-grading-15
	if routeClass != apphook.RouteClassTeam {
		// TODO-87 BUT NOT: a detector that returns no projection only WARNs, it
		// never refuses. Here, after the loop and ahead of every exit below, so a
		// refused request reports it too and one request logs it at most once.
		p.notePersonalProjectionState(logger, len(reqGrading.escalation), personalProjected, personalUnprojected)
	}
	esc := evaluateEscalation(pieces, escFindings, reqGrading.escalation, p.requestEscalationCeiling())
	p.escalationMetrics.evaluated.Add(1)
	p.escalationMetrics.lastCounted.Store(int64(esc.Counted))
	// TODO-72: a piece cut at pipeInputCap had its tail forwarded unscanned, so
	// esc.Counted is only a LOWER BOUND and this verdict may have let through a
	// request that should have escalated. Declared, not closed, in this release
	// (DEC-compliance-grading-26; chunked scanning is the next one) — the
	// counter and the log field below are what keep it from being silent.
	// spec: R-compliance-grading-17.S2
	countIsLowerBound := truncPieces > 0
	if countIsLowerBound {
		p.escalationMetrics.evaluatedOnTruncated.Add(1)
	}
	if esc.Skipped > 0 {
		// 🔴 THE WARN TASK 3.9 HANDED OVER. countDistinctHits is a pure function
		// with no request context, so it returns the number instead of logging it
		// and the logging obligation moves HERE, where request_id / trace_id /
		// span_id are on the logger (handle_dispatch stamps them via slog.With —
		// which is why this must be `logger` and never the package default).
		//
		// WHAT IT MEANS: these hits passed the confirmed + level + family filters
		// and STILL could not be resolved to a value, i.e. the detector's offsets
		// and the proxy's text disagree — a cross-process desync. It is not a
		// by-design exclusion: those never reach this number, precisely so this
		// WARN does not fire on every agent turn and stop being read.
		//
		// The request is NOT failed over it (§6 #11): an unresolvable hit is
		// simply not counted, which can only make escalation LESS likely — the
		// fail-open direction the sync detection budget prescribes. This line is
		// what keeps that fail-open from being silent.
		p.escalationMetrics.unresolvedHits.Add(int64(esc.Skipped))
		logger.Warn("filter: escalation counter could not resolve some confirmed hits to a value; "+
			"they were NOT counted (detector offsets and proxy text disagree)",
			"event.name", observability.EventProxyFilterEscalationUnresolved,
			"unresolved_hits", esc.Skipped, "pieces", len(pieces), "counted", esc.Counted)
	}
	// The request-level verdict row, filled by whichever request-level
	// conclusions are reached below (cumulative escalation, route policy, or
	// both) and emitted ONCE after both (TODO-171, DEC-compliance-grading-27).
	verdict := requestVerdict{
		TraceID: traceID, TenantID: orgID, VirtualKeyID: virtualKeyID,
		SeatID: seatID, SessionID: sessionID,
	}
	verdictAction := apphook.ActionAllow
	if esc.Rule != nil {
		p.escalationMetrics.triggered.Add(1)
		// 失败要显眼, inverted: this is the one line that says a request was
		// refused by an accumulation rather than by any single piece. Rule text
		// and counts only — every part of it comes from the administrator's
		// document, never from what was matched.
		logger.Info("filter: request escalated by the cumulative compliance rule",
			"event.name", observability.EventProxyFilterEscalated,
			"rule", esc.Rule.String(), "counted", esc.Counted, "pieces", len(pieces),
			"action", esc.Action.String(), "capped", esc.Capped,
			"already_refused", refusalAction != apphook.ActionAllow,
			// Same key as proxy.filter.input_truncated so the two lines join.
			"pieces_truncated", truncPieces,
			"counted_is_lower_bound", countIsLowerBound)

		// Record the conclusion as its OWN audit row (R-compliance-grading-18),
		// on BOTH routes since TODO-87. unit_ids name the content rows that were
		// counted: the proxy's own content-derived ids on a team route, the
		// detector's projection event ids on a personal route (escUnitIDs is
		// filled per route in the loop above).
		//
		// 🔴 The row itself is NOT built here any more (TODO-171,
		// DEC-compliance-grading-27): a route-policy violation below is the
		// OTHER request-level conclusion, and the verdict id derives from the
		// trace — one request, one row. Built once, after both decisions, by
		// emitRequestVerdict; a second row here would be absorbed by master's
		// ON CONFLICT (event_id) DO NOTHING and half the audit would vanish.
		// spec: R-compliance-grading-18
		units := make([]string, 0, len(esc.Units))
		for _, idx := range esc.Units {
			if id := escUnitIDs[idx]; id != "" {
				units = append(units, id)
			}
		}
		verdict.Rule = esc.Rule.String()
		verdict.Counted = esc.Counted
		verdict.UnitIDs = units
		verdict.CountedIsLowerBound = countIsLowerBound
		verdictAction = esc.Action

		// Enact it. Only ever a STRENGTHENING: a refusal already recorded by a
		// piece stands as-is (R-compliance-grading-15: 「SHALL NOT 弱于逐片段动作的
		// 最强项」), and the ceiling has already had its say inside
		// evaluateEscalation.
		if refusalAction == apphook.ActionAllow && esc.Action == apphook.ActionBlock {
			refusalAction = apphook.ActionBlock
			// A literal, not a rule rendering: the client is told a policy
			// refused them, never which rule or how many hits it took. Handing
			// the caller the count would turn the refusal into an oracle they can
			// probe. The administrator sees all of it on the audit row.
			refusalMsg = "request blocked by compliance policy"
		}
	}

	// ── Grading-driven route policy (task 11.2) ─────────────────────────────
	//
	// spec: R-compliance-grading-8 (判定发生在检测之后、provider 选择之前；不静默改路由；不外泄等级)
	//
	// After the loop because the levels only exist once every piece has been
	// scanned (cache hits included — escFindings is filled on both paths), and
	// before the deferred refusal so a refusal here takes the ONE guardrail
	// short-circuit below: nothing is forwarded, nothing is re-routed.
	//
	// Reads ONLY each finding's level + confirmed (applyGradingRoutePolicy); no
	// rule is re-run. An empty policy skips the whole block, which is what keeps
	// an org that never configured route_policy byte-identical to before.
	//
	// The operator's MAX_ACTION ceiling applies exactly as it does to the
	// cumulative rule (「天花板只压不抬」): with MAX_ACTION=warn the request is
	// forwarded and the capped conclusion is logged and counted, never silent.
	if len(reqGrading.routePolicy) > 0 {
		p.routePolicyMetrics.evaluated.Add(1)
		target := routeTargetFromContext(r.Context())
		var all []Finding
		for _, fs := range escFindings {
			all = append(all, fs...)
		}
		if action, reason := applyGradingRoutePolicy(all, target, reqGrading.routePolicy); action != apphook.ActionAllow {
			rule, _ := reqGrading.routePolicy.firstViolated(all, target)
			enforced, capped := p.requestEscalationCeiling().clamp(action)
			// The route-policy conclusion goes on the request-verdict row in
			// BOTH outcomes — refused, and capped by MAX_ACTION=warn (user
			// decision 2026-09-18: a capped request is L-high content that
			// really went outside the allow-list, the fact an audit most needs).
			// Config + the route's provider code + existing row ids only (DC5).
			// spec: R-compliance-grading-8.S1
			rpUnits := []string{}
			for _, idx := range rule.triggeringPieces(escFindings) {
				if id := escUnitIDs[idx]; id != "" {
					rpUnits = append(rpUnits, id)
				}
			}
			verdict.RoutePolicy = &routePolicyVerdict{
				MinLevel: rule.verdictMinLevel(), TargetProvider: target.Code, UnitIDs: rpUnits,
			}
			verdictAction = strongerVerdictAction(verdictAction, enforced)
			switch {
			case capped:
				p.routePolicyMetrics.capped.Add(1)
				logger.Info("filter: grading route policy would refuse this request, but the MAX_ACTION ceiling "+
					"let it through; content forwarded to a provider outside the allow-list",
					"event.name", observability.EventProxyFilterRoutePolicyCapped,
					"route_policy", reason, "min_level", rule.MinLevel, "target_provider", target.Code,
					"enforced", enforced.String())
			case enforced == apphook.ActionBlock:
				p.routePolicyMetrics.denied.Add(1)
				// Config + the route's own provider code only — never the matched
				// value, never which piece.
				logger.Info("filter: request refused by the grading route policy; nothing forwarded",
					"event.name", observability.EventProxyFilterRoutePolicyDenied,
					"route_policy", reason, "min_level", rule.MinLevel, "target_provider", target.Code,
					"already_refused", refusalAction != apphook.ActionAllow)
				if refusalAction == apphook.ActionAllow {
					refusalAction = apphook.ActionBlock
					refusalByRoutePolicy = true
				}
			}
		}
	}

	// ── The request-verdict row, emitted once (TODO-171) ───────────────────
	if verdict.Rule != "" || verdict.RoutePolicy != nil {
		verdict.Action = verdictAction.String()
		verdict.Now = time.Now()
		switch ev := p.buildVerdictRowOrWarn(logger, verdict); {
		case ev == nil:
		case routeClass == apphook.RouteClassTeam:
			teamEvents = append(teamEvents, ev)
		default:
			// Personal route: LOCAL self-view only (user decision V1). Never
			// teamEvents — master holds none of this route's content rows, so
			// every unit id would dangle there, and the personal/team isolation
			// of 2026-05-10 stays in force. Fence:
			// TestEscalation_PersonalRouteNoDoubleUpload.
			localVerdictEvents = append(localVerdictEvents, ev)
		}
	}

	// ── The deferred refusal, written here instead of inside the loop ────────
	//
	// Placed BEFORE the restore stash and the two post-loop signals below so a
	// refused request leaves this function exactly where it used to: no
	// placeholder state is handed to a response leg that will never run, and
	// neither the scan-coverage counter nor the degraded WARN fires for bytes
	// that never reached an upstream. That skip is deliberate and pre-existing —
	// see the comment on the truncation block.
	if refusalAction != apphook.ActionAllow {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		if refusalAction == apphook.ActionAnswer {
			// Re-bound under the name the write site has always used. The red-line
			// fence TestFence_GuardrailShortCircuitBodyIsNeverInterpolated keys its
			// four approved exemptions on these exact expressions
			// (`cannedAnswer.proto` / `.streaming` / `.text` + `model`), and each
			// entry states WHY that value cannot carry detector output. Renaming
			// them here would force four red-line exemptions to be re-approved
			// under new names for a value that has not changed — a worse outcome
			// than one alias line.
			cannedAnswer := refusalAnswer
			// 🔴 THE ONE WHITELISTED VARIABLE (TODO-178, user decision 2026-09-20,
			// R-compliance-canned-answer-10 — which SUPERSEDES the 「一律不插值」
			// sentence of R-compliance-canned-answer-3 and nothing else in it).
			//
			// Rendered HERE, at the single write site, and not inside the six-shape
			// synthesizer: writeCannedAnswer is the outlet for the six SHAPES, and
			// putting the substitution behind it would move it out of the scan range
			// of the red-line fence below — a fence that stopped looking is worse
			// than no fence. Here it stays an argument the fence must judge, which
			// is why guardrailVerbatimSources carries this exact expression with its
			// reason.
			//
			// The hits are computed from what this process already holds — the piece
			// text plus the detector's offsets, sliced by the same hitValue the
			// escalation counter uses — so nothing is added to any wire, event or
			// row. See canned_answer_variable.go for the masking rule and for the
			// three residual exposures the user accepted.
			answerText := renderCannedAnswerText(cannedAnswer.text, collectCannedAnswerHits(pieces, escFindings, escEvents), logger)
			if writeErr := writeCannedAnswer(w, cannedAnswer.proto, cannedAnswer.streaming, model, answerText); writeErr != nil {
				// planCannedAnswer already proved the shape is synthesizable, so
				// reaching here means the CLIENT went away mid-write (or the
				// writer was handed something it refuses). Either way the request
				// is still short-circuited — never forwarded — which is the half
				// that protects the content. Loud, because a synthesizer that
				// cannot synthesize what it just approved is a defect, not noise.
				logger.Error("filter: canned answer could not be written; request still refused, nothing forwarded",
					"event.name", "proxy.filter.canned_answer_write_failed",
					"protocol", cannedAnswer.proto.String(), "streaming", cannedAnswer.streaming,
					"error", writeErr.Error())
				return false
			}
			logger.Info("filter: request answered from policy (代答); nothing forwarded upstream",
				"event.name", "proxy.filter.answered",
				"protocol", cannedAnswer.proto.String(), "streaming", cannedAnswer.streaming,
				"answer_source", cannedAnswer.source, "answer_text_len", len(cannedAnswer.text),
				// Lengths only — never the text, never a category, never a fragment
				// (the same rule planCannedAnswer's WARN states).
				"answer_rendered_len", len(answerText),
				"degraded", refusalDegraded)
			return false
		}
		p.errors.Add(1)
		if refusalByRoutePolicy {
			// A constant, like every other refusal body: the client learns the
			// policy said "not to this provider" and what to do about it — never
			// the level, the rule or the matched value (an oracle for probing the
			// classification). The administrator has all of it in the log above.
			writeJSONError(w, http.StatusForbidden, "invalid_request_error",
				observability.ErrCodeComplianceRoutePolicyDenied,
				"Your organization's compliance policy does not allow content of this sensitivity "+
					"level to be sent to this model provider. Send it through a model provider your "+
					"organization approves for sensitive data (for example an intranet model), or "+
					"remove the sensitive content and try again.")
			return false
		}
		// Logged BEFORE the fallback below, so `reason` is still the detector's
		// own word (empty when it gave none) and not the constant the client is
		// about to be shown — byte-identical to what this line printed when it
		// lived inside the loop.
		logger.Info("filter: request blocked",
			"event.name", "proxy.filter.blocked",
			"reason", refusalMsg, "degraded", refusalDegraded)
		if refusalMsg == "" {
			refusalMsg = "request blocked by compliance policy"
		}
		writeJSONError(w, http.StatusForbidden, "invalid_request_error",
			"COMPLIANCE_BLOCKED", refusalMsg)
		return false
	}

	if restoreState != nil && len(restoreState.keys) > 0 {
		// Hang the placeholder→original state on the request context so the
		// response leg (non-streaming body restore + SSE restorer in serveRoute's
		// ModifyResponse) can swap the labels back. Same in-place WithContext
		// stash pattern as applyModelMappingToRequest — the caller keeps using
		// this *http.Request, and serveRoute derives its forwarding context from
		// r.Context() after this call. Absent for every request without a
		// restorable mask → the response leg pays one nil ctx lookup.
		*r = *r.WithContext(context.WithValue(r.Context(), ctxKeyMaskRestore, restoreState))
	}

	// Scan-coverage signal (2026-08-13, bugfix 20260813-pipe-input-cap-truncates-
	// silently). ONE aggregated line per request, never one per piece: an agent
	// turn carrying several large tool payloads truncates many pieces at once, and
	// per-piece lines would make the operator scroll past the very signal they are
	// looking for (「只记状态转变、不逐条记」, same posture as the degraded WARN below).
	//
	// WARN not INFO: unlike the action-ceiling cap — where the content IS examined
	// and the finding IS recorded, just not enforced — this content is never
	// examined at all. It produces no mask, no compliance event and no audit row,
	// so it is a genuine coverage hole in the compliance guarantee, not a policy
	// decision. request_id / trace_id / span_id come from the caller's logger
	// (handle_dispatch stamps them via slog.With), which is why this WARN must be
	// emitted on `logger` and never on the package-level slog default.
	//
	// Placed after the loop, alongside the degraded WARN, so it shares that
	// function's exit semantics: an ActionBlock returns early and skips both. That
	// is deliberate — a blocked request is refused outright, so none of its bytes
	// reached the upstream and counting them here would overstate the exposure the
	// counter exists to measure.
	if truncPieces > 0 {
		p.scanCoverage.truncatedPieces.Add(int64(truncPieces))
		p.scanCoverage.skippedBytes.Add(int64(truncSkippedBytes))
		logger.Warn("filter: content exceeded the detector input cap; the tail was forwarded to the upstream UNSCANNED",
			"event.name", observability.EventProxyFilterInputTruncated,
			"pieces_truncated", truncPieces,
			"pieces_total", len(pieces),
			// The aggregate's stand-in for the per-piece index a one-line-per-piece
			// form would have carried; enough to locate the offender in a re-run.
			"first_piece_index", truncFirstIdx,
			// BYTES, not characters — a 16 KiB cap is ~5,460 CJK characters.
			"cap_bytes", pipeInputCap,
			"total_bytes", truncTotalBytes,
			"scanned_bytes", truncScannedBytes,
			"skipped_bytes", truncSkippedBytes)
	}

	if degraded {
		// Hook unavailable for one or more pieces — those passed through
		// unfiltered. Surfaced so operators see degraded detection (失败要显眼);
		// the request is NOT failed (§6 #11 fail-open). Enriched (2026-06-13 RCA):
		// nil_resp = pipe dead (child unreachable); self_deg = child ran but
		// returned Degraded; hook_reason = the child's own DegradedReason; the
		// detect latency tells timeout-vs-error apart at a glance.
		logger.Warn("filter: hook degraded; affected content passed through unfiltered",
			"event.name", "proxy.filter.degraded",
			"pieces", len(pieces), "nil_resp", nilResp, "self_deg", selfDeg,
			"detect_ms", detectNanos/1e6, "hook_reason", hook.Status().DegradedReason,
			"body_bytes", len(bodyBytes))
	}

	// Per-request link-level trace (on-demand via AIKEY_PROXY_LOG_LEVEL=debug):
	// the full filter decision for ONE request — pieces scanned, masked count,
	// degrade state, and detect latency. The anomaly paths above are always WARN;
	// this is the steady-state trace for end-to-end debugging without a rebuild.
	logger.Debug("filter: decision",
		"event.name", "proxy.filter.decision",
		"pieces", len(pieces), "masked", maskedCount, "capped", cappedCount,
		"degraded", degraded,
		"detect_ms", detectNanos/1e6, "body_bytes", len(bodyBytes),
		"incremental", incremental, "route_class", routeClass,
		"cache_hits", cacheHits, "cache_miss", cacheMiss)

	if maskedCount == 0 {
		// Nothing changed — forward the original bytes verbatim.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return true
	}

	// Re-serialize with masked content. Only content string VALUES changed; the
	// envelope structure and string escaping are preserved by encoding/json.
	newBody, err := json.Marshal(parsed)
	if err != nil {
		// Should not happen (we just unmarshaled it). Fail-open with original.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		logger.Warn("filter: re-marshal failed; forwarding original",
			"event.name", "proxy.filter.remarshal_failed", "error", err)
		return true
	}
	// Through the chokepoint: it also refreshes GetBody, without which an
	// HTTP/2 retry replays the ORIGINAL buffered request and sends the UNMASKED
	// prompt upstream — a transport-level retry defeating DLP, with nothing
	// anywhere reporting it. See setRequestBody (oauth_inject.go).
	setRequestBody(r, newBody)
	r.Header.Set("Content-Length", itoaInt64(int64(len(newBody))))
	logger.Info("filter: request masked",
		"event.name", "proxy.filter.masked",
		"pieces_masked", maskedCount,
		"orig_bytes", len(bodyBytes),
		"masked_bytes", len(newBody))
	return true
}

// injectTenant overwrites the team event JSON's tenant_id with the authoritative
// org id the proxy resolved from the authenticated VK. The detector builds the
// event on a client that has no org context (tenant_id empty), and the master
// must not trust a client-self-reported tenant — so the trusted proxy stamps it
// from the VK's actual org. Fail-open: on parse error return the bytes unchanged
// (the master will reject a malformed event, which is more visible than dropping
// it here).
func injectTenant(eventJSON []byte, orgID string) []byte {
	if orgID == "" {
		return eventJSON
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &m); err != nil {
		return eventJSON
	}
	q, err := json.Marshal(orgID)
	if err != nil {
		return eventJSON
	}
	m["tenant_id"] = q
	out, err := json.Marshal(m)
	if err != nil {
		return eventJSON
	}
	return out
}

// injectVirtualKey stamps the proxy-authoritative virtual_key_id onto the team
// event JSON — the VK that triggered it, for per-seat attribution at a centralized
// gateway (one proxy node serves many employees). The proxy resolves the VK per
// request; it never crosses the detector pipe (credential stays in the proxy).
// Empty vk (non-team route / unresolved) → unchanged. Fail-safe like injectTenant:
// any parse/marshal error returns the original event. See 20260611 集中化网关归因改造.
func injectVirtualKey(eventJSON []byte, virtualKeyID string) []byte {
	if virtualKeyID == "" {
		return eventJSON
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &m); err != nil {
		return eventJSON
	}
	q, err := json.Marshal(virtualKeyID)
	if err != nil {
		return eventJSON
	}
	m["virtual_key_id"] = q
	out, err := json.Marshal(m)
	if err != nil {
		return eventJSON
	}
	return out
}

// injectSeat stamps the proxy-authoritative seat_id onto the team event JSON —
// the org seat of the human at the terminal (route.SeatID), the SAME field the
// usage + conversation-audit paths carry. The master compliance-audit page
// resolves the seat alias/email from this; without it, a pool-VK event's
// user_id (the detector's metadata.user_id = a Claude/session id) never matches
// a seat and the page shows a raw UUID. Empty seat (personal key / legacy) →
// unchanged, same fail-safe as injectVirtualKey. (2026-07-08 seat attribution.)
func injectSeat(eventJSON []byte, seatID string) []byte {
	if seatID == "" {
		return eventJSON
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &m); err != nil {
		return eventJSON
	}
	q, err := json.Marshal(seatID)
	if err != nil {
		return eventJSON
	}
	m["seat_id"] = q
	out, err := json.Marshal(m)
	if err != nil {
		return eventJSON
	}
	return out
}

// injectEventID overwrites the event's id with the proxy-derived audit-unit id
// (auditUnitID). It is the ONE place the proxy takes ownership of that field.
//
// WHY the proxy and not the detector (2026-09-08 拍板): the audit unit is
// «a stretch of violating content WITHIN ONE SESSION», and the session is a
// proxy-side concept — the detector runs with no session context at all (it is
// handed one content piece and nothing else). Deriving the id therefore has to
// happen wherever BOTH halves exist, and that is here. The alternative (adding a
// session scope to the pipe request so the detector could derive it) costs a
// proto bump and a cross-repo lockstep for zero behavioral gain.
//
// Fail-safe: an unparseable event or an empty id leaves the bytes untouched, so
// the detector's own id survives and the worst case degrades to the pre-fix
// behavior (a possible duplicate row) rather than to a 400 for an empty id.
func injectEventID(eventJSON []byte, eventID string) []byte {
	if eventID == "" {
		return eventJSON
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &m); err != nil {
		return eventJSON
	}
	q, err := json.Marshal(eventID)
	if err != nil {
		return eventJSON
	}
	m["event_id"] = q
	out, err := json.Marshal(m)
	if err != nil {
		return eventJSON
	}
	return out
}

// injectSession stamps the conversation session_id onto the team event JSON —
// resolved by resolveSessionID, the SAME source the conversation-audit observer
// uses, so the compliance audit drawer can open the conversation THREAD a
// flagged prompt belongs to. Empty session (no session header — e.g. codex,
// which the conversation-audit UI keys by trace id instead) → unchanged, same
// fail-safe as injectSeat. (2026-07-08.)
//
// 🔴 Correction (2026-08-09, F1a): this comment used to read "event_id joins
// the turn; session_id opens its thread". The first half was never true — see
// injectTraceID for why the compliance event_id joins nothing, and which field
// actually does.
func injectSession(eventJSON []byte, sessionID string) []byte {
	if sessionID == "" {
		return eventJSON
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &m); err != nil {
		return eventJSON
	}
	q, err := json.Marshal(sessionID)
	if err != nil {
		return eventJSON
	}
	m["session_id"] = q
	out, err := json.Marshal(m)
	if err != nil {
		return eventJSON
	}
	return out
}

// injectTraceID stamps THIS TURN's W3C trace id onto the team event JSON. It is
// the join key from a compliance event to the one conversation_records row for
// the same turn, which is what lets the compliance-audit page show the prompt
// as the user actually typed it (pre-mask) behind an "eye" control.
//
// WHY a new field instead of reusing event_id (the 2026-08-09 F1a decision):
// the two id spaces are unrelated and always have been.
//
//   - compliance event_id — minted in the DETECTOR CHILD PROCESS by its own
//     newEventID() CSPRNG. The proxy never sees it before the detector returns.
//   - conversation event_id — the proxy's per-request W3C trace id, stored by
//     the conversation-audit observer as ConversationRecord.EventID.
//
// So `compliance_events.event_id = conversation_records.event_id` matches
// nothing, and the audit page's `?event=` deep link built on that assumption
// has been dead since it shipped. trace_id is the key that actually joins.
//
// CARDINALITY: one turn produces N compliance events (one per flagged content
// piece — the caller appends inside the per-piece loop) but exactly ONE
// conversation record. All N share this trace id, so the relationship is N:1
// and the join must be read in that direction.
//
// PRIVACY (DC5 / 方案 §6 不变量 #1 unaffected BY THIS FUNCTION): this is a
// correlation id, not content. No prompt text is added to the upload here — the
// master stores the key only, and the raw turn stays wherever
// conversation_records lives.
//
// 🔴 2026-08-11 — the old text went on to claim "the original text still never
// leaves the user's box" and listed three guards including "content-free intake
// wire + DisallowUnknownFields at master" and "the detector's local-only
// ContextSnippet". Those two guards are GONE by design: the intake wire declares
// `context_snippet`, and ContextSnippet is no longer local-only (the detector's
// gate is tiered — `PrivacyTier >= 3` on the team branch, seeded ON for a fresh
// Team/Cluster install). What this function does is still content-free; the
// system-wide claim it appealed to is not. The surviving system-wide statement
// is 「原文不出**客户信任边界**」 — never onto an AiKey-operated server.
//
// Empty trace (no observer context on the route → no conversation record to
// join to anyway) → unchanged, same fail-safe as injectSeat/injectSession.
func injectTraceID(eventJSON []byte, traceID string) []byte {
	if traceID == "" {
		return eventJSON
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &m); err != nil {
		return eventJSON
	}
	q, err := json.Marshal(traceID)
	if err != nil {
		return eventJSON
	}
	m["trace_id"] = q
	out, err := json.Marshal(m)
	if err != nil {
		return eventJSON
	}
	return out
}

// injectActionTaken rewrites the team event JSON's `action_taken` to the verdict
// the proxy ACTUALLY applied, used when a block-type action ceiling downgraded
// the detector's decision (方案② 2026-08-10, filter_content.go actionCeiling).
//
// WHY the proxy overwrites a field the detector authored: the detector decides
// on CONTENT and has no idea which block the piece came from — the route class
// is the only context that crosses the pipe. The ceiling is a proxy-side policy,
// so the proxy is the only party that can keep the audit record truthful. An
// event that says `mask` while the bytes went upstream verbatim is worse than no
// event: it is the "虚假安全感" this whole scan-scope investigation started from.
//
// 🔴 KNOWN GAP — PERSONAL/LOCAL ROUTE IS NOT COVERED. On a personal route the
// detector uploads its own event straight to the local self-view intake
// (AIKEY_COMPLIANCE_LOCAL_INTAKE, cmd/detector/main.go emitEvent) and the proxy
// never touches those bytes. So a Personal/Trial self-view can still show
// `action_taken=mask` for a capped tool-block finding. Closing that needs the
// ceiling to cross the pipe so the detector caps at source — a wire-contract
// change, deliberately not taken here. Tracked in
// workflow/CI/bugfix/2026-08-10-compliance-tool-result-scan-scope.md §5.5.
//
// Fail-safe like the other injectors: any parse/marshal error returns the
// original event unchanged (a malformed event the master rejects is louder than
// one silently dropped here).
func injectActionTaken(eventJSON []byte, action string) []byte {
	if action == "" {
		return eventJSON
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &m); err != nil {
		return eventJSON
	}
	q, err := json.Marshal(action)
	if err != nil {
		return eventJSON
	}
	m["action_taken"] = q
	out, err := json.Marshal(m)
	if err != nil {
		return eventJSON
	}
	return out
}

// injectAnswerSource stamps `answer_source` onto the team event JSON: WHICH tier
// of the three-level fallback supplied the sentence the user actually saw
// (`rule` / `level` / `org`, spelled identically to the detector's
// actionpolicy.AnswerSource and to design §4b's wire field).
//
// WHY IT MATTERS TO A HUMAN: an administrator looking at a 代答 row needs to
// know whether that sentence came from the rule they just edited or from the
// org-wide default they set up a year ago and forgot. Without it the audit page
// can say "the user was answered" but not "answered with whose text", which is
// the only actionable half.
//
// 🔴 `none` IS NEVER STAMPED. It is not a fourth tier — it means no tier had a
// text, and such a request is not a canned answer at all: applyInboundFilter
// degrades it to ActionBlock and the row's action_taken is `block`
// (R-compliance-canned-answer-2.S2). Callers must not pass it, and the guard
// below is defense in depth rather than policy.
//
// ⚠️ master stopped rejecting an out-of-domain value on 2026-09-12 (task 1.20:
// 200 + NULL column + WARN, no longer 400), so a wrong value here is silently
// dropped at the far end. The domain is held on this side or nowhere.
//
// Fail-safe like the rest of the inject* family: any parse/marshal problem
// returns the event unchanged — an annotation must never cost the audit record.
func injectAnswerSource(eventJSON []byte, source string) []byte {
	switch source {
	case "rule", "level", "org":
	default:
		return eventJSON
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &m); err != nil {
		return eventJSON
	}
	q, err := json.Marshal(source)
	if err != nil {
		return eventJSON
	}
	m["answer_source"] = q
	out, err := json.Marshal(m)
	if err != nil {
		return eventJSON
	}
	return out
}

// injectWireLabels stamps, onto each finding of the team event JSON, the
// numbered placeholder that finding's value was ACTUALLY forwarded upstream as
// (`{{PHONE_1}}`) — the seventh member of the inject* family and, like the other
// six, a fact the detector cannot know and the proxy just produced.
//
// WHY this exists: the snippet the detector records shows its NUMBERLESS token
// (`{{PHONE}}`), because numbering is request-scoped and happens here, after the
// detector has already built the event. A member reading their self-view was
// therefore shown a string that was never sent, and two hits of the same entity
// type in one prompt were indistinguishable. This closes that gap by carrying
// the RESULT of the numbering rather than moving the rule (方案 L, update doc
// 20260810-合规事件携带命中片段原文 §16.3; 方案 C — moving numbering into the
// detector — was costed in §16.4 and declined).
//
// HOW the join works: spanLabels is keyed on [start,end) byte offsets into the
// head this piece sent to the detector, and a finding's start_offset/end_offset
// are offsets into that SAME payload in the SAME raw frame (the detector remaps
// findings back to the raw frame before both the event and the mask metadata are
// built). So this is an EQUAL JOIN on an offset pair — the proxy is not
// re-deriving which entity is where, it is looking up an answer it already
// computed. No parsing of the snippet, no regex, no re-application of any rule.
//
// 🔴 PER-PIECE ONLY. Offsets are relative to one piece's head, so piece #2's
// span [10,21) is a completely different substring from piece #1's [10,21). The
// caller must pass the map produced by THIS piece and apply it to THIS piece's
// event. Applying a request-wide map would silently mislabel findings.
//
// 🔴 A FINDING WITH NO MATCH KEEPS AN EMPTY wire_label, AND THAT IS THE POINT.
// Three important cases land there and all of them are correct:
//   - the finding's policy action is `audit` (record it, forward the bytes
//     unchanged) — e.g. CN_ADDRESS, whose shipped default is audit. It is in the
//     event but never in the mask plan, so it has no span here. Its raw value
//     went upstream verbatim, and naming a placeholder for it would tell the
//     compliance dashboard the value was redacted when it was not — the same
//     false-safety failure injectActionTaken exists to prevent one field over.
//   - an action ceiling capped the piece: the Mask branch never runs, no labels
//     are allocated, this function is never called for that piece.
//   - one of the three restore degrade paths fired: the mask still applies, the
//     numbering does not, and renumberRestorables returns a nil map.
//
// So "has a wire label" reads as "this value really did go out under this name",
// and only that. Fenced by TestInjectWireLabels_AuditFindingStaysUnlabelled.
//
// Fail-safe like the other injectors: any parse/marshal problem returns the
// original event unchanged — a wire label is an annotation, and losing it must
// never cost the audit record itself.
func injectWireLabels(eventJSON []byte, spanLabels map[[2]int]string) []byte {
	if len(spanLabels) == 0 {
		return eventJSON
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &m); err != nil {
		return eventJSON
	}
	raw, ok := m["findings"]
	if !ok {
		return eventJSON
	}
	var findings []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &findings); err != nil {
		return eventJSON
	}
	stamped := 0
	for _, f := range findings {
		var start, end int
		if err := json.Unmarshal(f["start_offset"], &start); err != nil {
			continue
		}
		if err := json.Unmarshal(f["end_offset"], &end); err != nil {
			continue
		}
		label, hit := spanLabels[[2]int{start, end}]
		if !hit {
			continue
		}
		q, err := json.Marshal(label)
		if err != nil {
			continue
		}
		f["wire_label"] = q
		stamped++
	}
	if stamped == 0 {
		return eventJSON
	}
	nf, err := json.Marshal(findings)
	if err != nil {
		return eventJSON
	}
	m["findings"] = nf
	out, err := json.Marshal(m)
	if err != nil {
		return eventJSON
	}
	return out
}

// itoaInt64 formats an int64 without pulling strconv into a hot file (mirrors
// the tiny-helper convention used elsewhere in the proxy).
func itoaInt64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
