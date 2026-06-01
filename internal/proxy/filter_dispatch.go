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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

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
	logger *slog.Logger,
) (proceed bool) {
	hook := p.filterHook
	if hook == nil {
		return true // no filter installed — pass through
	}
	if r.Body == nil {
		return true
	}

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
	pieces, parsed, ok := extractFilterableContent(bodyBytes)
	if !ok || len(pieces) == 0 {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return true
	}

	var (
		maskedCount int
		degraded    bool
	)
	for i := range pieces {
		resp := hook.Detect(r.Context(), &apphook.Request{
			Direction:   apphook.DirectionInbound,
			Payload:     []byte(pieces[i].text),
			TargetModel: model,
			// RequestID best-effort from the inbound trace header; child uses it
			// only for log correlation. Empty is fine.
			RequestID: r.Header.Get("x-request-id"),
			// UserRole left empty for MVP — PoC uses default-tenant pack
			// (方案 §5.4.5: PoC 期 child 忽略 user_role, 统一用 default).
		})
		if resp == nil { // defensive: a nil response is treated as degraded allow
			degraded = true
			continue
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
			pieces[i].setText(string(m))
			maskedCount++

		case apphook.ActionWarn:
			logger.Info("filter: content warned (passed through)",
				"event.name", "proxy.filter.warned", "reason", resp.Reason)

		default: // ActionAllow (incl. degraded fail-open)
			if resp.Degraded {
				degraded = true
			}
		}
	}

	if degraded {
		// Hook unavailable for one or more pieces — those passed through
		// unfiltered. Surfaced so operators see degraded detection (失败要显眼);
		// the request is NOT failed (§6 #11 fail-open).
		logger.Warn("filter: hook degraded; affected content passed through unfiltered",
			"event.name", "proxy.filter.degraded")
	}

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
