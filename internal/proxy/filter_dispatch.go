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
func capRuneBoundary(s string, cap int) int {
	if cap >= len(s) {
		return len(s)
	}
	b := cap
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
func (p *Proxy) applyInboundFilter(
	w http.ResponseWriter,
	r *http.Request,
	model string,
	routeSource string,
	orgID string,
	virtualKeyID string,
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
	pieces, parsed, ok := extractUserContent(bodyBytes)
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
		degraded    bool
		nilResp     int // detector unreachable (pipe dead) — resp == nil
		selfDeg     int // detector returned Degraded=true (it ran but couldn't decide)
		detectNanos int64
		cacheHits   int // content-hash 缓存命中(复用判定、跳过 detector)
		cacheMiss   int // content-hash 缓存未命中(真扫 + 回填)
	)

	// content-hash 缓存(设计 §4):仅当缓存启用时才算 scope/detectorVer。缓存关闭
	// (p.filterCache == nil)时下面循环根本不碰 hash → 不付 content-hash 代价(INV-6)。
	// scope = 隔离桶(同会话历史复用、跨会话不串);detectorVer 进 key 让 detector
	// 重启自动失效旧条目;per-entry TTL 兜底 in-place pack pull 的陈旧 clean 判定。
	var cacheScopeKey, detectorVer string
	if p.filterCache != nil {
		cacheScopeKey = cacheScope(r, parsed, virtualKeyID)
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
			if v, ok := p.filterCache.Get(cacheScopeKey, ckey); ok {
				resp = &apphook.Response{Action: v.action, MutatedPayload: []byte(v.maskedHead), Reason: v.reason}
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
			if p.filterCache != nil && resp != nil && !resp.Degraded {
				p.filterCache.Put(cacheScopeKey, ckey, maskVerdict{
					action:     resp.Action,
					maskedHead: string(resp.MutatedPayload),
					reason:     resp.Reason,
				})
			}
		}
		if resp == nil { // defensive: a nil response is treated as degraded allow
			degraded = true
			nilResp++
			continue
		}
		// Team-routed only: collect the event the detector handed back for the
		// proxy to forward to master (the deferred upload sends them). Guard on
		// routeClass so the proxy stays self-consistent even if a child ever
		// returned an Event on a personal route — those must never be uploaded.
		// The proxy stamps the authoritative tenant_id = the VK's resolved org
		// (NOT user input): the detector runs on a client with no org context,
		// and the master must not trust a client-self-reported tenant.
		// (update doc 20260603 §2.1)
		if routeClass == apphook.RouteClassTeam && len(resp.Event) > 0 {
			// Stamp BOTH authoritative attribution fields the proxy resolved (the
			// detector has neither): tenant_id = the VK's org, virtual_key_id = the
			// VK itself (per-seat attribution at a centralized gateway). The VK never
			// crosses the detector pipe. See 20260611 集中化网关归因改造.
			teamEvents = append(teamEvents, injectVirtualKey(injectTenant(resp.Event, orgID), virtualKeyID))
		}

		switch resp.Action {
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
			m := resp.MutatedPayload
			if len(m) == 0 {
				// Mask verdict but no payload — leave this piece unchanged.
				logger.Warn("filter: Mask verdict with empty MutatedPayload; leaving content unchanged",
					"event.name", "proxy.filter.mask_empty")
				continue
			}
			// Masked head (the scanned first pipeInputCap bytes) + the untouched
			// tail (forwarded raw, never scanned — same as the detector's own cap).
			pieces[i].setText(string(m) + tail)
			maskedCount++

		case apphook.ActionWarn:
			logger.Info("filter: content warned (passed through)",
				"event.name", "proxy.filter.warned", "reason", resp.Reason)

		default: // ActionAllow (incl. degraded fail-open)
			if resp.Degraded {
				degraded = true
				selfDeg++
			}
		}
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
		"pieces", len(pieces), "masked", maskedCount, "degraded", degraded,
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
