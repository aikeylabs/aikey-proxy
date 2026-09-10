// chat_completions_bridge.go — dialect reconciliation for OAuth credentials.
//
// # The problem, stated as two independent axes
//
// Whether a hop speaks Chat Completions or the Responses API is a property of
// each SIDE, decided separately:
//
//   - INBOUND — what the client speaks. The client states it on every request
//     by choosing the URL (/v1/chat/completions or /v1/responses), so this axis
//     needs no configuration and cannot go stale.
//   - OUTBOUND — what the credential's upstream speaks. A ChatGPT OAuth
//     (codex) upstream serves ONLY Responses; a self-hosted relay almost always
//     serves only Chat Completions. This axis is NOT derivable from the request
//     and is what the operator configures.
//
// All four combinations occur. Two are passthrough; the two that differ need a
// translator pair, and both directions are registered.
//
// # Why the outbound axis is keyed on the upstream host
//
// "Where may this OAuth token be sent" and "what does that place speak" are
// both properties of the same host, so one config entry answers both. Keying
// them separately would let a deployment answer one and forget the other, and
// each failure is silent in a different way.
//
// # Invariants
//
//  1. With the bridge disabled (the default) behaviour is byte-for-byte what it
//     was before this file existed, refusal wording included.
//  2. An OAuth credential can only reach the compiled-in codex upstream unless
//     the operator enumerated another host. That hardcoding is a security
//     property, not a shortcut: an OAuth access token is not a rotatable key,
//     it is the subscription, and whoever receives it holds the account.
//  3. Translation is client-facing ONLY. The response leg is wrapped OUTSIDE
//     the stream drainer, so usage extraction, the conversation-audit observer
//     and the collector all keep reading the upstream-native body. A defect
//     here can corrupt what a client reads; it cannot change what is billed.
//  4. Dialects that already agree are never touched — no translation, no path
//     rewrite, no state armed.
//
// Regression fences: TestBridge_* in chat_completions_bridge_test.go.
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	_ "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator/pairs/openai_responses"
	_ "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator/pairs/responses_openai"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	chatCompletionsSuffix = "/chat/completions"
	responsesSuffix       = "/responses"
)

// BridgeUpstreamRule is one permitted OAuth destination and the dialect it
// serves — the proxy-native form of config.BridgeUpstream.
//
// The proxy deliberately does not import internal/config: the supervisor is the
// wiring layer that reads config and injects, which is how every other proxy
// setting arrives (SetConsoleURL, SetClusterNode, …). Keeping that direction
// means the proxy stays testable without a config file.
type BridgeUpstreamRule struct {
	Host    string
	Dialect string
}

// bridgeRuntime is the immutable per-generation view of the bridge settings.
// Swapped atomically so a config reload cannot race a request read.
type bridgeRuntime struct {
	enabled bool
	byHost  map[string]translator.Format
}

var emptyBridgeRuntime = &bridgeRuntime{byHost: map[string]translator.Format{}}

func newBridgeRuntime(enabled bool, rules []BridgeUpstreamRule) *bridgeRuntime {
	rt := &bridgeRuntime{enabled: enabled, byHost: make(map[string]translator.Format, len(rules))}
	for _, r := range rules {
		host := strings.ToLower(strings.TrimSpace(r.Host))
		if host == "" {
			continue
		}
		switch r.Dialect {
		case "responses":
			rt.byHost[host] = translator.FormatOpenAIResponses
		case "chat_completions":
			rt.byHost[host] = translator.FormatOpenAI
		}
	}
	return rt
}

// SetChatCompletionsBridge injects the operator's bridge settings.
//
// Disabled with no upstreams — the shipped default — reproduces the pre-bridge
// behaviour exactly. Safe to call on a live proxy: readers take the pointer.
func (p *Proxy) SetChatCompletionsBridge(enabled bool, upstreams []BridgeUpstreamRule) {
	p.bridge.Store(newBridgeRuntime(enabled, upstreams))
}

func (p *Proxy) bridgeRT() *bridgeRuntime {
	if p == nil {
		return emptyBridgeRuntime
	}
	if rt := p.bridge.Load(); rt != nil {
		return rt
	}
	return emptyBridgeRuntime
}

// allowsHost reports whether an OAuth credential may target this host. The
// compiled-in codex upstream is always allowed; everything else must be listed.
func (rt *bridgeRuntime) allowsHost(host string) bool {
	_, ok := rt.byHost[strings.ToLower(host)]
	return ok
}

// dialectForUpstream answers what a destination speaks.
//
// The codex upstream is matched by HOST rather than by literal string so the
// loopback test hook (AIKEY_PROXY_TEST_CODEX_BASE_URL) resolves to the same
// answer as production — otherwise every hermetic E2E would exercise a
// different branch from the one that ships.
func (rt *bridgeRuntime) dialectForUpstream(baseURL string) translator.Format {
	host := strings.ToLower(hostOf(baseURL))
	if host == "" {
		return ""
	}
	// An explicit operator declaration wins over the compiled-in default. The
	// default encodes what chatgpt.com serves, which is a fact about ONE host;
	// once a deployment has said what a host speaks, that statement is strictly
	// more specific. It also cannot weaken anything: the allowlist governs
	// WHERE a token may go, and this governs only what shape is sent there.
	if f, ok := rt.byHost[host]; ok && f != "" {
		return f
	}
	// The codex upstream is matched by HOST rather than literal string so the
	// loopback test hook (AIKEY_PROXY_TEST_CODEX_BASE_URL) resolves the same way
	// production does — otherwise every hermetic E2E would exercise a different
	// branch from the one that ships.
	if host == strings.ToLower(hostOf(codexUpstreamBaseURL())) {
		return translator.FormatOpenAIResponses
	}
	return rt.byHost[host]
}

// isCodexEndpoint reports whether a destination is the compiled-in ChatGPT
// codex endpoint, as opposed to something an operator pointed the credential at.
//
// It matters because that endpoint has a URL convention no other upstream
// shares: it serves /responses directly off its base, with no version segment,
// so the client's /v1 has to be stripped (bugfix 2026-07-19, codex 404
// {"detail":"Not Found"}). Applying that strip to a relay would remove a
// segment the relay needs.
//
// The discriminator is DECLARATION, not address. A host the operator listed is
// theirs and follows the generic version-dedup rule even if it happens to sit
// at the same address the codex default was redirected to — which is exactly
// what the hermetic E2Es do. This is the same precedence dialectForUpstream
// uses: an explicit declaration beats a compiled-in assumption.
func (rt *bridgeRuntime) isCodexEndpoint(baseURL string) bool {
	host := strings.ToLower(hostOf(baseURL))
	if host == "" {
		return false
	}
	if _, declared := rt.byHost[host]; declared {
		return false
	}
	return host == strings.ToLower(hostOf(codexUpstreamBaseURL()))
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// dialectForPath reads the inbound axis off the URL. Returns "" for paths that
// are not an OpenAI-family chat surface (/v1/models, /v1/messages, …), which
// the bridge leaves alone entirely.
func dialectForPath(path string) translator.Format {
	p := strings.TrimSuffix(path, "/")
	switch {
	case strings.HasSuffix(p, chatCompletionsSuffix):
		return translator.FormatOpenAI
	case strings.HasSuffix(p, responsesSuffix):
		return translator.FormatOpenAIResponses
	default:
		return ""
	}
}

// rewriteDialectPath swaps the dialect suffix, preserving whatever prefix the
// entry point left in place (/v1, or nothing).
func rewriteDialectPath(path string, to translator.Format) string {
	trimmed := strings.TrimSuffix(path, "/")
	var prefix string
	switch {
	case strings.HasSuffix(trimmed, chatCompletionsSuffix):
		prefix = strings.TrimSuffix(trimmed, chatCompletionsSuffix)
	case strings.HasSuffix(trimmed, responsesSuffix):
		prefix = strings.TrimSuffix(trimmed, responsesSuffix)
	default:
		return path
	}
	switch to {
	case translator.FormatOpenAIResponses:
		return prefix + responsesSuffix
	case translator.FormatOpenAI:
		return prefix + chatCompletionsSuffix
	default:
		return path
	}
}

type bridgeCtxKey struct{}

// bridgeState is armed on the request context when translation engages, and
// read again on the response leg.
//
// It carries the (from, to) pair so the response leg reverses the SAME hop the
// request took. Hardcoding a direction here worked while only one existed and
// would silently translate backwards the moment a second one did.
type bridgeState struct {
	from, to translator.Format
	stream   *translator.StreamState

	// deStream marks a request the CLIENT asked to answer in one piece that we
	// had to send upstream as a stream anyway. The Codex backend serves only
	// stream:true (measured: shape matrix S03/S06/S07 all answer 400 "Stream
	// must be set to true"), so a plain `client.chat.completions.create(...)`
	// — no stream= argument, the single most common call in the Chat
	// Completions ecosystem — had nothing to be translated INTO. The response
	// leg reads this and collapses the SSE back into one JSON body, so the
	// client never learns the hop streamed.
	deStream bool
}

func armBridge(r *http.Request, from, to translator.Format) *http.Request {
	return armBridgeState(r, &bridgeState{from: from, to: to, stream: &translator.StreamState{}})
}

// armBridgeDeStreamed is armBridge for the case above: the upstream leg
// streams, the client leg does not.
func armBridgeDeStreamed(r *http.Request, from, to translator.Format) *http.Request {
	return armBridgeState(r, &bridgeState{
		from: from, to: to, stream: &translator.StreamState{}, deStream: true,
	})
}

func armBridgeState(r *http.Request, st *bridgeState) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), bridgeCtxKey{}, st))
}

func bridgeFromContext(ctx context.Context) *bridgeState {
	st, _ := ctx.Value(bridgeCtxKey{}).(*bridgeState)
	return st
}

// dialectRefusal is a lane-neutral refusal. Each OAuth lane renders it in its
// own error envelope — one predicate, N adapters, rather than N predicates.
type dialectRefusal struct {
	Status    int
	ErrorType string
	Code      string
	Message   string
}

// bridgeOrRejectDialect is the single entry point every OAuth lane calls.
//
// It returns the request to continue with (translated and re-pathed when the
// two axes disagree and the bridge is on) and a refusal when they disagree and
// it is off.
//
// `existingBase` is the route/account's already-resolved endpoint, passed so
// this can ask the SAME question resolveOAuthUpstream will answer — the
// outbound dialect is a property of the destination, so the destination has to
// be known here rather than guessed.
func (p *Proxy) bridgeOrRejectDialect(
	r *http.Request, oauthCode, protocolType, existingBase string, logger *slog.Logger,
) (*http.Request, *dialectRefusal) {
	// Every other provider's OAuth upstream equals its API-key upstream and
	// already serves what its clients speak; there is nothing to reconcile.
	if oauthCode != "openai" {
		return r, nil
	}
	inbound := dialectForPath(r.URL.Path)
	if inbound == "" {
		// Not a chat surface (/v1/models and friends). Untouched.
		return r, nil
	}

	rt := p.bridgeRT()
	base := p.oauthUpstreamBase(oauthCode, protocolType, existingBase, logger)
	outbound := rt.dialectForUpstream(base)
	if outbound == "" {
		// Fail closed. Reaching here means an OAuth credential resolved to a
		// host that is neither the compiled-in codex upstream nor a configured
		// one, so nothing here knows what shape to send — and guessing is how a
		// request gets answered in the wrong dialect with no way to tell.
		if logger != nil {
			logger.Error("oauth upstream has no known dialect",
				"event.name", observability.EventProxyRequestDialectUnsupported,
				"error.code", observability.ErrCodeOAuthResponsesOnly,
				"upstream_host", hostOf(base),
				"url.path", r.URL.Path,
			)
		}
		return r, &dialectRefusal{
			Status:    http.StatusBadGateway,
			ErrorType: "server_error",
			Code:      observability.ErrCodeOAuthResponsesOnly,
			Message: "This credential resolved to an upstream (" + hostOf(base) + ") whose API dialect is " +
				"not declared. Add it to chat_completions_bridge.upstreams with its dialect, or remove the " +
				"custom base URL so the credential uses its provider default.",
		}
	}

	// Axes agree — the overwhelmingly common case, and the one that must stay
	// free of any rewriting. The single exception is a request the destination
	// cannot serve in ANY dialect; see deStreamSameDialect.
	if inbound == outbound {
		return p.deStreamSameDialect(r, inbound, rt, base, logger)
	}

	if !rt.enabled {
		reason := dialectMismatchReason(inbound, outbound, r.URL.Path)
		if logger != nil {
			logger.Warn("oauth upstream does not serve this endpoint",
				"event.name", observability.EventProxyRequestDialectUnsupported,
				"error.code", observability.ErrCodeOAuthResponsesOnly,
				"error.message", reason,
				"url.path", r.URL.Path,
			)
		}
		return r, &dialectRefusal{
			// oauthResponsesOnlyStatus (422), not 400: adopted from the
			// pre-dial gate this sits in front of, whose reasoning applies
			// unchanged here — the refusal must stay visible to a direct SDK
			// while landing inside a relay's retry range, because "this
			// credential cannot serve this dialect" is exactly a
			// try-another-channel condition. Parameter-translation refusals
			// keep 400: those are malformed-for-us requests, a different fact.
			Status:    oauthResponsesOnlyStatus,
			ErrorType: "invalid_request_error",
			Code:      observability.ErrCodeOAuthResponsesOnly,
			Message:   reason,
		}
	}

	out, refusal := p.translateRequestLeg(r, inbound, outbound, rt.isCodexEndpoint(base), logger)
	if refusal != nil {
		return r, refusal
	}
	return out, nil
}

// deStreamSameDialect is the one case where a request needs NO dialect
// translation and still cannot be forwarded as it was sent.
//
// A native /responses client asking for a whole answer at once is speaking
// exactly the dialect the Codex backend speaks — nothing to translate — and the
// backend refuses it anyway, because it serves stream:true and nothing else
// (measured: shape matrix 2026-09-10 cells S03, S06 and S07 all answer 400
// "Stream must be set to true"). Until now that request was refused at the
// pre-dial gate with a message telling the caller to change their client.
//
// # Why this lives in the bridge rather than in codex_shape_normalize.go
//
// Because it is two rewrites, not one. Asking the upstream to stream is only
// half of it; the response has to be collapsed back into a single body, and the
// normalizer only ever sees the request. Splitting the pair across two files is
// how they drift apart. The bridge already owns exactly this pairing for
// translated traffic, and the collapsing machinery is the same code — the only
// difference here is that from and to are equal, so no dialect translation
// happens on the way back.
//
// # Why it is behind the same switch
//
// Invariant 1 says a deployment that never opted in behaves byte-for-byte as it
// did, refusal wording included. Serving a request that used to be refused is a
// better outcome, but it is still a different one: it reaches the upstream, it
// bills, and a relay that was retrying the 422 on another channel now stays on
// this one. That belongs to the operator, and it leaves a kill switch if the
// collapsing ever misbehaves.
//
// Returns the request unchanged — never a refusal — when this does not apply.
// The pre-dial gate downstream still refuses the un-rewritten case, which is
// what keeps the switched-off behaviour identical.
func (p *Proxy) deStreamSameDialect(
	r *http.Request, dialect translator.Format, rt *bridgeRuntime, base string, logger *slog.Logger,
) (*http.Request, *dialectRefusal) {
	// Cheapest checks first: the common case must not even read the body.
	if !rt.enabled || dialect != translator.FormatOpenAIResponses || !rt.isCodexEndpoint(base) {
		return r, nil
	}
	if r.Body == nil || r.Body == http.NoBody || r.Method != http.MethodPost {
		return r, nil
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return r, &dialectRefusal{
			Status:    http.StatusBadRequest,
			ErrorType: "invalid_request_error",
			Code:      "BRIDGE_REQUEST_READ_FAILED",
			Message:   "Could not read the request body to check whether this credential's upstream can serve it: " + err.Error(),
		}
	}
	// Already streaming, or not a JSON object we understand: put it back exactly
	// as it came and leave it alone. setRequestBody rather than the bridged
	// variant, so the inbound Content-Length header is not disturbed either.
	if !gjson.ValidBytes(body) || gjson.GetBytes(body, "stream").Bool() {
		setRequestBody(r, body)
		return r, nil
	}
	rewritten, err := sjson.SetBytes(body, "stream", true)
	if err != nil {
		setRequestBody(r, body)
		return r, nil // cannot rewrite: let the pre-dial gate refuse it as before
	}

	// from == to: the response leg collapses the stream but performs no dialect
	// translation, because the terminal event's `response` object already IS the
	// non-streaming body for this dialect.
	out := armBridgeDeStreamed(r, dialect, dialect)
	setBridgedRequestBody(out, rewritten)
	if logger != nil {
		logger.Info("dialect bridge: de-streaming a native Responses request the upstream cannot serve non-streaming",
			"event.name", observability.EventProxyBridgeEngaged,
			"inbound_dialect", string(dialect),
			"outbound_dialect", string(dialect),
			"url.path", out.URL.Path,
			"stream", false,
			"de_streamed", true,
		)
	}
	return out, nil
}

// dialectMismatchReason explains a refusal in terms of what the upstream
// actually serves.
//
// The Responses-upstream wording is produced by oauthUpstreamRejectsPath, which
// is left exactly as it was: it is the message users have been acting on since
// 2026-07-13, and its remedy ("use a Responses-API client such as codex") is
// still the right one when the bridge is off.
func dialectMismatchReason(inbound, outbound translator.Format, path string) string {
	if outbound == translator.FormatOpenAIResponses {
		return oauthUpstreamRejectsPath("openai", path)
	}
	return "This credential's upstream serves the Chat Completions API (/chat/completions). " +
		"The client called " + path + " (Responses API). Use a Chat Completions client, " +
		"or enable chat_completions_bridge to have AiKey translate between the two."
}

// translateRequestLeg converts the body, rewrites the path and arms the
// response leg.
func (p *Proxy) translateRequestLeg(
	r *http.Request, inbound, outbound translator.Format, codexUpstream bool, logger *slog.Logger,
) (*http.Request, *dialectRefusal) {
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return nil, &dialectRefusal{
			Status:    http.StatusBadRequest,
			ErrorType: "invalid_request_error",
			Code:      "BRIDGE_REQUEST_READ_FAILED",
			Message:   "Could not read the request body to translate it for this credential's upstream: " + err.Error(),
		}
	}

	// The model rides through unchanged: the upstream validates model names
	// itself, and substituting one would answer a different question than the
	// caller asked.
	model := gjson.GetBytes(body, "model").String()
	streaming := gjson.GetBytes(body, "stream").Bool()

	// De-streaming, and why it is keyed on the DESTINATION rather than on the
	// outbound dialect: "only stream:true is served" is a measured property of
	// the Codex backend, not of the Responses API. api.openai.com serves
	// /responses non-streaming happily, and so does any relay an operator
	// declares as Responses-speaking. Forcing the upstream to stream for those
	// would buy nothing and would change a working request's wire form, so the
	// rewrite is confined to the one host that requires it.
	//
	// The rewrite is upstream-only: the client is answered in the shape it
	// asked for, by the response leg (chat_completions_bridge_destream.go).
	deStream := !streaming && codexUpstream
	translated, tErr := translator.DefaultRegistry().TranslateRequest(
		r.Context(), inbound, outbound, model, body, streaming || deStream)
	if tErr != nil {
		if logger != nil {
			logger.Warn("dialect bridge: request translation refused",
				"event.name", observability.EventProxyRequestDialectUnsupported,
				"error.code", tErr.Code,
				"error.message", tErr.Message,
				"param", tErr.Param,
				"url.path", r.URL.Path,
			)
		}
		return nil, &dialectRefusal{
			Status:    tErr.HTTPStatus,
			ErrorType: "invalid_request_error",
			Code:      tErr.Code,
			Message:   tErr.Message,
		}
	}

	out := armBridge(r, inbound, outbound)
	if deStream {
		out = armBridgeDeStreamed(r, inbound, outbound)
	}
	// Rewrite BOTH Path and RawPath: a stale RawPath wins over Path when
	// net/url re-encodes, which would forward the original dialect's route to an
	// upstream that has no such route.
	out.URL.Path = rewriteDialectPath(out.URL.Path, outbound)
	out.URL.RawPath = ""
	setBridgedRequestBody(out, translated)

	if logger != nil {
		logger.Info("dialect bridge engaged",
			"event.name", observability.EventProxyBridgeEngaged,
			"inbound_dialect", string(inbound),
			"outbound_dialect", string(outbound),
			"url.path", out.URL.Path,
			"stream", streaming,
			"de_streamed", deStream,
		)
	}
	return out, nil
}

// setBridgedRequestBody installs the translated body.
//
// setRequestBody (oauth_inject.go) keeps Body, ContentLength and GetBody in
// sync; the only thing left to do here is drop the inbound Content-Length
// HEADER, which is a separate thing from the ContentLength FIELD and would
// otherwise still advertise the untranslated body's byte count.
func setBridgedRequestBody(r *http.Request, body []byte) {
	setRequestBody(r, body)
	r.Header.Del("Content-Length")
}

// translateBridgedResponse converts a non-streaming upstream body back to the
// inbound dialect. Returns the input unchanged when nothing was armed.
//
// Called from ModifyResponse AFTER token extraction, so the usage that reaches
// the ledger is read from the upstream-native body (invariant 3).
func translateBridgedResponse(ctx context.Context, body []byte, logger *slog.Logger) ([]byte, *translator.TranslateError) {
	st := bridgeFromContext(ctx)
	if st == nil {
		return body, nil
	}
	// Same dialect in and out: nothing to translate. This is the de-streamed
	// native /responses client (deStreamSameDialect) — the collapsing already
	// produced the body that dialect returns for a non-streaming call, and
	// there is no (X -> X) pair registered to ask anyway.
	if st.from == st.to {
		return body, nil
	}
	out, tErr := translator.DefaultRegistry().TranslateNonStream(ctx, st.from, st.to, body)
	if tErr != nil {
		if logger != nil {
			logger.Error("dialect bridge: response translation failed",
				"event.name", observability.EventProxyBridgeTranslateFailed,
				"error.code", tErr.Code,
				"error.message", tErr.Message,
			)
		}
		return nil, tErr
	}
	return out, nil
}
