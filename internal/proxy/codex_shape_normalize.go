// codex_shape_normalize.go — request-shape normalization for the ChatGPT
// Codex backend (OAuth codex accounts, personal and pool).
//
// Why this exists: the Codex backend enforces request-shape rules that plain
// OpenAI Responses clients do not know about, and it answers every violation
// with HTTP 400 — a status no relay retries. A client that sends `input` as a
// string, omits `store`, or passes `temperature` therefore fails on an OAuth
// codex credential with no fallback anywhere in the chain, while the same
// request succeeds against api.openai.com. The rules were MEASURED, not read
// from documentation: 25 shapes were sent through the real account pool on
// 2026-09-10 (workflow/CI/research/codex-shape-matrix-2026-09/README.md, raw
// rows results/20260910T021253Z.tsv, config table shape-rules.yaml).
//
// What is rewritten here, and why each rewrite is safe (user ruling
// 2026-09-10「用户绝对高可用 + 日志充分」):
//
//	| rule                      | backend 400 message            | action                                   | cells          |
//	|---------------------------|--------------------------------|------------------------------------------|----------------|
//	| `input` is a JSON string  | Input must be a list           | wrap as one user message (lossless)      | S01, S20, S21  |
//	| `store` is not false      | Store must be set to false     | force false (the backend never stores)   | S08, S09       |
//	| max_output_tokens /       | Unsupported parameter: <name>  | strip and RECORD (a fallback to another  | S10, S11,      |
//	| temperature / truncation /|                                | Codex-backed relay would not honor them | S16, S17       |
//	| metadata present          |                                | either; refusing only drops the traffic) |                |
//	| top_p (any value, null    | Unsupported parameter: top_p   | strip and RECORD (same reasoning)        | staging        |
//	| included)                 |                                |                                          | 2026-09-11 (1) |
//
// (1) Not a spike cell: measured through the bridge on master2 staging after a
// Chat Completions client sending top_p got a hard 400 while temperature and
// max_tokens were already stripped. Bugfix: workflow/CI/bugfix/2026-09-11-codex-rejects-top-p.md
//
// Deliberately NOT rewritten here: `stream` and `instructions`.
//
// `instructions` because absent/empty is accepted upstream (spike S04/S05).
//
// `stream` because the fix belongs one layer out, not in this table. The
// backend requires stream:true, but honoring that for a client that asked for
// one whole body is only half a rewrite: the RESPONSE has to be collapsed back
// too, and this function cannot do that — it only ever sees the request. So the
// dialect bridge owns both halves (chat_completions_bridge_destream.go), which
// keeps the pair of rewrites in one place where they cannot drift apart.
//
// oauthUpstreamRejectsShape below therefore still refuses a non-streaming
// request, and that is not dead code — it is the SWITCHED-OFF behavior. With
// the bridge enabled, both a bridged Chat Completions client and a native
// /responses one arrive here already rewritten to stream:true and pass; with it
// disabled nothing rewrites them and this refusal is what the caller gets,
// unchanged since 2026-09-10. That is bridge invariant 1: a deployment that
// never opted in behaves exactly as it did, refusal wording included.
//
// Every rewrite is visible: the field names travel to the client in the
// X-Aikey-Normalized response header and to the operator in one INFO line per
// request (reportCodexNormalization, wired into ModifyResponse). Values are
// never logged.
//
// Placement: called from resolveOAuthUpstream's "openai" branch — the ONE point
// where every OAuth dispatch lane (personal binding, registry token, probe,
// pool) already knows the request is bound for the Codex backend; the same
// spot captureCodexModel uses. Never call it for API-key openai traffic:
// api.openai.com accepts all of these shapes.
//
// spec: R-tokenhub-pool-fallback-7.S1 非 Codex 形状的请求不得以 400 断掉兜底链
// Why: roadmap20260320/技术实现/阶段9-商业化版本/tokenhub-pool-fallback/proposal.md 拍板点 8
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// codexUnsupportedParams are the top-level Responses fields the Codex backend
// rejects with "Unsupported parameter: <name>" (spike S10/S11/S16/S17). `user`
// was never isolated on the real backend (S17 carried user + metadata and only
// metadata was reported), so it is deliberately not on this list.
var codexUnsupportedParams = []string{"max_output_tokens", "temperature", "truncation", "metadata", "top_p"}

const (
	codexNormalizedInput       = "input"
	codexNormalizedStore       = "store"
	codexNormalizedStripPrefix = "strip:"
)

// normalizeCodexRequest rewrites a Codex-bound Responses request in place and
// returns the request carrying the list of rewrites in its context (empty list
// = nothing changed; the request is then returned untouched, byte for byte).
func normalizeCodexRequest(r *http.Request) *http.Request {
	if r == nil || r.Body == nil || r.Body == http.NoBody || r.Method != http.MethodPost {
		return r
	}
	if !strings.HasSuffix(strings.TrimSuffix(r.URL.Path, "/"), "/responses") {
		return r
	}
	raw, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(raw))
		return r
	}
	out, changes := normalizeCodexBody(raw)
	if len(changes) == 0 {
		r.Body = io.NopCloser(bytes.NewReader(raw))
		return r
	}
	setRequestBodyBytes(r, out)
	return r.WithContext(context.WithValue(r.Context(), ctxKeyCodexNormalized, changes))
}

// normalizeCodexBody applies the rule table to one JSON object body. A body
// that is not a JSON object (or needs no change) is returned as-is with no
// changes, so the caller never re-serializes what it did not touch.
// nolint:gocritic // unnamedResult: naming these collides with the function's
// own `changes` local (tried 2026-09-10, build broke: "changes redeclared").
// The doc comment above already says what both results are.
func normalizeCodexBody(raw []byte) ([]byte, []string) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return raw, nil
	}
	var changes []string
	if in, ok := fields["input"]; ok && jsonRawStartsWith(in, '"') {
		var text string
		if err := json.Unmarshal(in, &text); err == nil {
			// Exactly the shape the Codex CLI sends (and the spike's accepted B0):
			// one user message whose content is a single input_text part.
			list, err := json.Marshal([]map[string]any{{
				"role":    "user",
				"content": []map[string]any{{"type": "input_text", "text": text}},
			}})
			if err == nil {
				fields["input"] = list
				changes = append(changes, codexNormalizedInput)
			}
		}
	}
	if !jsonRawIs(fields["store"], "false") {
		fields["store"] = json.RawMessage("false")
		changes = append(changes, codexNormalizedStore)
	}
	for _, name := range codexUnsupportedParams {
		if _, present := fields[name]; present {
			delete(fields, name)
			changes = append(changes, codexNormalizedStripPrefix+name)
		}
	}
	if len(changes) == 0 {
		return raw, nil
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return raw, nil
	}
	return out, changes
}

func jsonRawStartsWith(raw json.RawMessage, first byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == first
}

func jsonRawIs(raw json.RawMessage, literal string) bool {
	return string(bytes.TrimSpace(raw)) == literal
}

// setRequestBodyBytes installs a rewritten body so every consumer agrees on
// its length: the transport writes ContentLength, GetBody serves retries, and
// a stale inbound Content-Length header must not survive the rewrite.
func setRequestBodyBytes(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	r.Header.Del("Content-Length")
}

// codexNormalizationsFromContext returns the rewrites stashed by
// normalizeCodexRequest (nil when the request was not rewritten).
func codexNormalizationsFromContext(ctx context.Context) []string {
	changes, _ := ctx.Value(ctxKeyCodexNormalized).([]string)
	return changes
}

// reportCodexNormalization runs on the response leg (ModifyResponse, next to
// persistCodexLastModelIfSuccessful): it tells the client which fields were
// rewritten (X-Aikey-Normalized) and leaves one INFO line per rewritten
// request so an operator can answer "why did this request behave differently
// from api.openai.com" from the log alone. Field NAMES only — never values.
func reportCodexNormalization(resp *http.Response) {
	if resp == nil || resp.Request == nil {
		return
	}
	changes := codexNormalizationsFromContext(resp.Request.Context())
	if len(changes) == 0 {
		return
	}
	joined := strings.Join(changes, ",")
	resp.Header.Set(HeaderAikeyNormalized, joined)
	tc := traceFromContext(resp.Request.Context())
	slog.Info("codex: request shape normalized for the ChatGPT Codex backend",
		"event.name", observability.EventProxyCodexRequestNormalized,
		"normalized", joined,
		"url.path", resp.Request.URL.Path,
		"status_code", resp.StatusCode,
		"trace_id", tc.TraceID,
		"request_id", tc.RequestID,
		"upstream_request_id", resp.Header.Get(HeaderAikeyUpstreamRequestID),
	)
}

// codexNonStreamReason is the actionable message for the one shape the Codex
// backend rejects that aikey cannot rewrite yet (spike S03/S06/S07:
// "Stream must be set to true").
const codexNonStreamReason = "This key is backed by a ChatGPT OAuth account, whose upstream only serves streaming Responses requests (stream:true). " +
	"This request asked for a non-streaming response. Send stream:true, or use an API-key credential for this client."

// oauthUpstreamRejectsShape is the body-shape half of the pre-dial gate whose
// path half is oauthUpstreamRejectsPath: for a Codex-persona OAuth credential
// it names the reason a POST /responses body cannot be served upstream even
// after normalization. Empty reason = forward. Only non-streaming bodies
// qualify today; every other rejected shape is rewritten by
// normalizeCodexRequest instead (input list, store=false, stripped parameters).
//
// Why refuse here rather than relay the backend's 400 (user ruling 2026-09-10,
// 「可用性优先」止血): 400 is a client error no relay retries, so a
// non-streaming SDK client behind tokenhub failed with no fallback; 422 is
// inside the relay's retry range and the request is served by the next
// channel. The message still tells a direct client what to change.
//
// The body is read and restored byte-for-byte; the persona check mirrors the
// normalizer (canonical openai and the Mock simulating it both answer
// "openai" from oauthInjectionProvider).
//
// spec: R-tokenhub-pool-fallback-7.S1 非 Codex 形状的请求不得以 400 断掉兜底链
func oauthUpstreamRejectsShape(oauthCode string, r *http.Request) string {
	if oauthCode != "openai" || r == nil || r.Body == nil || r.Body == http.NoBody || r.Method != http.MethodPost {
		return ""
	}
	if !strings.HasSuffix(strings.TrimSuffix(r.URL.Path, "/"), "/responses") {
		return ""
	}
	raw, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return "" // not a JSON object: let the upstream judge it
	}
	if jsonRawIs(fields["stream"], "true") {
		return ""
	}
	return codexNonStreamReason
}
