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
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// pipeInputCap bounds how many bytes of a content piece the proxy sends over the
// detector pipe. It matches the detector's own NLP input cap (16KB): the
// detector only scans the first 16KB of any piece, so transferring more is pure
// waste — and a huge piece (e.g. a 180KB context) blocks the pipe long enough to
// stall the request for seconds and desync the IPC (→ the hook degrades). We cap
// the transfer and re-attach the untouched tail after masking (same forwarded
// result, fast IPC). Snapped to a rune boundary so a multibyte char never splits.
const pipeInputCap = 16 * 1024

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
// engineer correlating an audit event with cache behaviour relies on it.
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
	if r.Body == nil {
		return true
	}

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
		// restoreState collects numbered-placeholder → original mappings for
		// restorable masks (B3). Allocated lazily on the first restorable mask;
		// stashed on the request context for the response leg. Memory-only,
		// request-scoped, never logged/persisted (B3 拍板 2026-08-06).
		restoreState *maskRestore
	)

	// content-hash 缓存(设计 §4):仅当缓存启用时才算 scope/detectorVer。缓存关闭
	// (p.filterCache == nil)时下面循环根本不碰 hash → 不付 content-hash 代价(INV-6)。
	// scope = 隔离桶(同会话历史复用、跨会话不串);detectorVer 进 key 让 detector
	// 重启自动失效旧条目;per-entry TTL 兜底 in-place pack pull 的陈旧 clean 判定。
	// scope 复用调用方已解析的 sessionID(serveRoute → resolveSessionID → sessionid
	// fingerprint 表):Claude 专有 header 之外的 provider(kimi/codex/cursor/cline …)
	// 现在也能拿到会话级隔离桶,不再降级到 vk/global 让多会话共桶。见 cacheScope 注释。
	var cacheScopeKey, detectorVer string
	if p.filterCache != nil {
		cacheScopeKey = cacheScope(sessionID, parsed, virtualKeyID)
		detectorVer = hook.Status().Version
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
		}
		// content-hash 缓存:历史里逐字未变的内容(每轮重发)命中缓存即复用判定、
		// 跳过 detector IPC;只有新增/被改写(miss)才真扫。命中时合成一个等价 resp,
		// 走下面同一套处理(mask/allow/...)。缓存关闭(p.filterCache==nil)则直接真扫。
		var resp *apphook.Response
		var ckey string
		if p.filterCache != nil {
			ckey = cacheKey(detectorVer, hashHead(head)) // level-2 key (scope is separate)
			// 读侧 block 守卫(用户拍板 2026-08-08,与写侧不入缓存配套):即便缓存里
			// 残留了历史 block verdict(理论上写侧已不再写入;此处兜底进程内 pre-fix
			// 污染 + 防写侧未来回归),也当作 miss、落到下方真扫按最新策略重判 —— block
			// 是安全决策不复用陈旧拒绝。仅精确排除 ActionBlock,mask/warn/allow 命中路径
			// 逐字不变(它们 action != ActionBlock,条件恒真)。
			if v, ok := p.filterCache.Get(cacheScopeKey, ckey); ok && v.action != apphook.ActionBlock {
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
		if resp == nil { // 缓存 miss 或缓存关闭 → 真扫
			if p.filterCache != nil {
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
			// 只缓存"确定性"判定:degraded(超时/fail-open)与 nil 不缓存,否则会把
			// "没扫成"误记成 allow、下轮命中缓存就放行(违反 INV-2)。
			//
			// BLOCK 不入缓存(用户拍板 2026-08-08,安全边界修复):block(ActionBlock)是
			// 安全关键决策,每次都必须按【最新策略/pack】重新走 detector 判定,绝不复用
			// 缓存的陈旧拒绝。WHY:①缓存命中回放不调 detector(见上方 Get 分支),若把 block
			// 入缓存,则管理员放宽策略或 in-place pack swap(childhook.go 不 bump
			// detectorVersion,见 filter_cache.go PACK FRESHNESS/TTL 注释)后,陈旧 block
			// 仍会持续 403,且 sliding TTL 命中续期近乎永久 —— 放宽后无法立即生效;②block
			// 走拒绝路径不转发上游,缓存省下的那一次 detector 调用收益可忽略,ROI 为负。
			// mask/warn/allow 缓存行为保持不变(它们转发上游,复用判定收益实在)。
			// 隐患溯源:CN_ADDRESS 本身无 block 档,但其他 entity 的 HighRiskBlock
			// (policy.go HighRiskBlock)已在用这条链 → 当前生产就有此隐患。
			// 配套读侧守卫见上方 Get 分支(v.action != ActionBlock)。
			if p.filterCache != nil && resp != nil && !resp.Degraded && resp.Action != apphook.ActionBlock {
				// maskedHead is cached in the detector's NUMBERLESS token form —
				// per-request numbering happens AFTER cache replay so numbers stay
				// request-scoped (同请求内按出现顺序编号) instead of leaking a stale
				// numbering across turns.
				// event: cached so a cache HIT can re-emit the same audit event (see
				// maskVerdict.event). Stored as handed over — never mutated in place
				// (injectTenant/VirtualKey/Seat/Session all return fresh slices), so the
				// async uploader and the cache can share the bytes read-only.
				p.filterCache.Put(cacheScopeKey, ckey, maskVerdict{
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

		// ── ACTION CEILING (方案② 2026-08-10) ────────────────────────────────
		// The piece's ceiling comes from the SAME table row that made its block
		// type scannable at all (blockScanPolicy, filter_content.go). Tool blocks
		// are scanned so their findings are RECORDED, and capped so the 216
		// gitleaks-derived `block` rules can never fire on an agent's file reads.
		// Everything else keeps ceilingFull, i.e. byte-identical behaviour.
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
			if capped {
				ev = injectActionTaken(ev, pieces[i].ceiling.String())
			}
			teamEvents = append(teamEvents, ev)
		}

		switch action {
		case apphook.ActionBlock:
			// Refuse the whole request — one content piece contained content the
			// policy blocks (e.g. full private key, batch customer data). Restore
			// the original body for any error-path logging; do NOT forward.
			p.errors.Add(1)
			logger.Info("filter: request blocked",
				"event.name", "proxy.filter.blocked",
				"reason", resp.Reason, "degraded", resp.Degraded)
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			msg := resp.Reason
			if msg == "" {
				msg = "request blocked by compliance policy"
			}
			writeJSONError(w, http.StatusForbidden, "invalid_request_error",
				"COMPLIANCE_BLOCKED", msg)
			return false

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
			if len(resp.Restorables) > 0 {
				if restoreState == nil {
					restoreState = newMaskRestore()
					// Hand the state the process-wide fidelity counters so the
					// request leg's "issued" and the response leg's "restored"
					// land in ONE place without a per-request lifecycle hook
					// (方案 §3.2 L3 保真率指标). Counts only.
					restoreState.fid = &p.maskFidelity
				}
				masked = renumberRestorables(head, masked, resp.Restorables, restoreState, logger)
			}
			// Masked head (the scanned first pipeInputCap bytes) + the untouched
			// tail (forwarded raw, never scanned — same as the detector's own cap).
			pieces[i].setText(masked + tail)
			maskedCount++

		case apphook.ActionWarn:
			logger.Info("filter: content warned (passed through)",
				"event.name", "proxy.filter.warned", "reason", resp.Reason)

		case apphook.ActionAllow: // incl. degraded fail-open
			if resp.Degraded {
				degraded = true
				selfDeg++
			}

		default:
			// Unknown / future Action value. childhook converts the child's raw
			// wire byte straight to Action (childhook.go), so a misbehaving child
			// or a protocol version skew can yield a value outside the known set.
			// Fail-OPEN per §6 #11 (a detector anomaly must not block traffic),
			// but surface it LOUDLY (失败要显眼) and count it as degraded so it is
			// visible in metrics/alerts and never silently treated as a clean
			// Allow verdict. Without this the request would slip through unscanned
			// with zero signal (regression guarded by 2026-06-22 review).
			logger.Warn("filter: unknown apphook action; forwarding as degraded fail-open",
				"event.name", "proxy.filter.unknown_action",
				"action", int(resp.Action), "reason", resp.Reason)
			degraded = true
			selfDeg++
		}
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
	r.Body = io.NopCloser(bytes.NewReader(newBody))
	r.ContentLength = int64(len(newBody))
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
// PRIVACY (DC5 / 方案 §6 不变量 #1 unaffected): this is a correlation id, not
// content. No prompt text is added to the upload by this function, and the
// original text still never leaves the user's box — the master stores the key
// only, and the raw turn stays wherever conversation_records lives. The three
// existing guards (content-free intake wire + DisallowUnknownFields at master,
// the detector's local-only ContextSnippet, the proxy not persisting bodies)
// all keep holding.
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
