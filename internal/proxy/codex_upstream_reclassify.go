// codex_upstream_reclassify.go — response-leg re-labeling of the ChatGPT Codex
// backend's 400s that are NOT the client's fault.
//
// The problem, measured rather than reasoned (2026-09-10, live pool channel #3
// on api.pingtoken.ai, spike cells M04s/M04n in
// workflow/CI/research/codex-shape-matrix-2026-09/results/20260910T061800Z.tsv):
// the channel advertised six models; for `gpt-5.4-mini` the backend answered
//
//	400 {"detail":"The 'gpt-5.4-mini' model is not supported when using Codex
//	     with a ChatGPT account."}
//
// on BOTH the streaming and the non-streaming leg. That is not a bad request —
// it is the pool saying "I cannot serve this at all". But 400 sits outside every
// relay's retry range (tokenhub's own default is documented in its source as
// "retry for 1xx, 3xx, 4xx except 400/408, 5xx except 504/524"; the production
// deployment runs 100-199,300-399,401-599), so the fallback chain dies on it.
// All 13 cells of that run stayed on use_channel=["3"] — the third-party
// channel in the same group, which carries the very same model, was never even
// tried, and the client ate a hard 400.
//
// So this file does the mirror image of the pre-dial gates in
// codex_shape_normalize.go: those refuse BEFORE dialing when the REQUEST shape
// cannot be served; this one re-labels AFTER dialing when the UPSTREAM says the
// request cannot be served for a reason that is about the account, not the
// client. Both end at 422 for the same reason: 422 is inside the relay's retry
// range, is not auto-retried by OpenAI/Anthropic SDKs, and does not trip
// tokenhub's channel auto-disable (only 401 does).
//
// Why a table and not an if: the set of "the pool cannot serve this" upstream
// messages will grow (model lists change, backends add refusals). A table keeps
// every entry next to the evidence that produced it and keeps the predicate a
// single expression. Anything not in the table is forwarded byte for byte —
// a genuine client error must stay a client error, or every relay would retry
// a request that cannot succeed anywhere (R-tokenhub-pool-fallback-7 BUT NOT).
//
// spec: R-tokenhub-pool-fallback-7 池自身服务不了的请求 MUST NOT 以 400 出现（否则中转不兜底）
// Why: roadmap20260320/技术实现/阶段9-商业化版本/tokenhub-pool-fallback/proposal.md 拍板点 12
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// codexUpstream400Rule maps one measured upstream refusal to the aikey code
// that makes it recoverable. `match` is compared case-insensitively against the
// whole response body, and deliberately excludes the model name so the rule
// generalises to every model the backend refuses.
type codexUpstream400Rule struct {
	id    string
	match string
	code  string
}

var codexUpstream400Rules = []codexUpstream400Rule{
	{
		id:    "model_not_supported",
		match: "is not supported when using codex with a chatgpt account",
		code:  observability.ErrCodeOAuthModelUnsupported,
	},
}

// codexUpstreamErrorBodyLimit bounds what we are willing to buffer in order to
// judge an error body. Real refusals are a couple of hundred bytes; anything
// larger is forwarded untouched rather than held in memory.
const codexUpstreamErrorBodyLimit = 64 << 10

// codexUpstream400Code returns the aikey error code for an upstream response,
// or "" when the response must be forwarded verbatim.
func codexUpstream400Code(status int, body []byte) string {
	if status != http.StatusBadRequest || len(body) == 0 {
		return ""
	}
	lower := strings.ToLower(string(body))
	for _, rule := range codexUpstream400Rules {
		if strings.Contains(lower, rule.match) {
			return rule.code
		}
	}
	return ""
}

// markCodexUpstream records that this request was pointed at the ChatGPT Codex
// backend. Called from resolveOAuthUpstream's two Codex exits.
func markCodexUpstream(r *http.Request) *http.Request {
	if r == nil {
		return nil
	}
	return r.WithContext(context.WithValue(r.Context(), ctxKeyCodexUpstream, true))
}

func codexUpstreamFromContext(ctx context.Context) bool {
	on, _ := ctx.Value(ctxKeyCodexUpstream).(bool)
	return on
}

// reclassifyCodexUpstream400 runs in ModifyResponse, next to
// reportCodexNormalization. It is a no-op for every response except a 400 from
// the Codex backend whose body matches the rule table.
func reclassifyCodexUpstream400(resp *http.Response) {
	if resp == nil || resp.Request == nil || resp.Body == nil {
		return
	}
	if resp.StatusCode != http.StatusBadRequest || !codexUpstreamFromContext(resp.Request.Context()) {
		return
	}
	// A content-coded body would have to be decoded to be judged, and guessing
	// the coding wrong would corrupt a passthrough. Leave it alone.
	if enc := strings.TrimSpace(resp.Header.Get("Content-Encoding")); enc != "" && !strings.EqualFold(enc, "identity") {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, codexUpstreamErrorBodyLimit+1))
	if err != nil || len(raw) > codexUpstreamErrorBodyLimit {
		// Cannot judge it without buffering an unbounded body: re-attach what we
		// read in front of the rest so the client still gets every byte.
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(raw), resp.Body), resp.Body}
		return
	}
	_ = resp.Body.Close()
	code := codexUpstream400Code(resp.StatusCode, raw)
	if code == "" {
		resp.Body = io.NopCloser(bytes.NewReader(raw)) // byte-identical passthrough
		return
	}

	upstreamReason := codexUpstreamReason(raw)
	message := "This key is backed by a ChatGPT OAuth account whose upstream refused this request: " + upstreamReason +
		" Use a model this account can serve, or ask your administrator to route this model to a different channel."
	origin := resp.Header.Get(HeaderAikeyErrorOrigin) // the upstream is still the ROOT cause; only the status is ours
	body := aikeyErrorEnvelope("invalid_request_error", code, message, origin, nil)

	original := resp.StatusCode
	resp.StatusCode = http.StatusUnprocessableEntity
	resp.Status = strconv.Itoa(http.StatusUnprocessableEntity) + " " + http.StatusText(http.StatusUnprocessableEntity)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set(HeaderAikeyUpstreamStatus, strconv.Itoa(original))
	resp.Header.Set(HeaderAikeyErrorSource, code)

	tc := traceFromContext(resp.Request.Context())
	slog.Warn("codex: upstream refused a request this pool cannot serve — status re-labeled so a relay can fail over",
		"event.name", observability.EventProxyCodexUpstreamReclassified,
		"error.code", code,
		"upstream_status", original,
		"url.path", resp.Request.URL.Path,
		"trace_id", tc.TraceID,
		"request_id", tc.RequestID,
		"upstream_request_id", resp.Header.Get(HeaderAikeyUpstreamRequestID),
	)
}

// codexUpstreamReason pulls the human sentence out of the backend's error body.
// The Codex backend answers {"detail":"..."}; an OpenAI-shaped {"error":{...}}
// is handled too so a future backend change does not silently produce an empty
// reason. Falls back to a trimmed copy of the body.
func codexUpstreamReason(raw []byte) string {
	var envelope struct {
		Detail string `json:"detail"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) == nil {
		if s := strings.TrimSpace(envelope.Detail); s != "" {
			return s
		}
		if s := strings.TrimSpace(envelope.Error.Message); s != "" {
			return s
		}
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
