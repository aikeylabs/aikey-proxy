package mcp

// callrecord.go — recording every tools/call, including the refused ones.
//
// # 🔴 Why the outcome is OBSERVED rather than declared
//
// handleToolsCall and executeUpstream between them have a dozen terminal
// branches: not granted, frozen, backend disabled, malformed arguments, no
// transport, credential missing, circuit open, upstream error, success. The
// obvious implementation — a `record(...)` call in each branch — is wrong for a
// reason this repo has met before: the next person adds a thirteenth branch, and
// the call that was refused there simply never appears in the audit trail. There
// is no symptom. The console looks fine.
//
// So the recorder does not ask the branches to tell it anything. It wraps the
// ResponseWriter, and the JSON-RPC writers in rpcerror.go — which EVERY branch
// must go through in order to answer at all — stamp the outcome on the way out.
// A new branch is recorded by construction, because a branch that answers
// nothing is not a branch, it is a hang.
//
// spec:  workflow/CI/requirements/2026-08-20-mcp-gateway.md  R10 (a refusal is
//        a record) · R26 (observe, do not declare) · R27 (the three gates in
//        front of raw retention) · R29 (two session columns, not one)
// design: roadmap20260320/技术实现/阶段8-平台化/MCP网关/openspec/changes/aikey-mcp-gateway/tasks.md P7
//
// Fence: TestEveryRPCWriterStampsAnOutcome (callrecord_test.go) discovers
// the writers by scanning the file rather than listing them, so a NEW writer
// that forgets to stamp goes red without anyone remembering to add it.
//
// # 🔴 What is NOT recorded, and why that is not a hole
//
// Failures that happen before a tool is named — authentication, Origin,
// protocol negotiation, an unknown Mcp-Session-Id — are transport-level. They
// are not tool calls, and recording them as such would invent rows for calls
// that were never made, in a table an administrator reads to answer "who ran
// what". They are visible in the proxy's logs and in /health/mcp instead.
//
// Everything from the moment a tools/call body exists IS recorded, refusals
// included (R10). A refusal costs nothing — there is no cost field on this
// record at all, so "recorded" and "billed" cannot be conflated by accident.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/sessionid"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/uaattribution"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// CallSink receives one finished call record.
//
// 🔴 Deliberately NOT an uploader. The sink writes locally and returns; getting
// the record to the control plane is a separate, retrying rail (P7 task 7.1).
// A sink that posted synchronously would put a customer's tool call behind our
// control plane's availability — the exact coupling the isolation shell exists
// to prevent.
//
// Implementations must not block: they are called on the request goroutine
// after the response has been written.
type CallSink interface {
	RecordCall(ctx context.Context, rec mcpwire.CallRecord)
}

// outcomeSink is what the RPC writers stamp. Implemented by *callRecorder.
type outcomeSink interface {
	noteOutcome(code mcpwire.ErrorCode, isError bool)
}

// noteOutcome stamps the answer a writer is about to send, if this writer is
// being recorded. A no-op for every request that is not a tools/call.
func noteOutcome(w http.ResponseWriter, code mcpwire.ErrorCode, isError bool) {
	if s, ok := w.(outcomeSink); ok {
		s.noteOutcome(code, isError)
	}
}

// callRecorder accumulates one call's record and wraps the ResponseWriter.
type callRecorder struct {
	http.ResponseWriter
	rec     mcpwire.CallRecord
	started time.Time
	// noted is set by the FIRST writer to answer. First wins because that is
	// the answer the client actually received; a later write (there should be
	// none) cannot change what was sent.
	noted   bool
	code    mcpwire.ErrorCode
	isError bool
}

// beginCall starts a record. It never fails: a call that cannot be given an id
// is still recorded, with a WARN, because losing the row is worse than losing
// the id's unguessability (this id is a database key, not a credential).
func (h *Handler) beginCall(w http.ResponseWriter, r *http.Request, ident Identity, slug string) *callRecorder {
	now := time.Now()
	return &callRecorder{
		ResponseWriter: w,
		started:        now,
		rec: mcpwire.CallRecord{
			CallID:    h.mintCallID(r),
			OrgID:     ident.OrgID,
			SeatID:    ident.SeatID,
			SessionID: r.Header.Get(mcpwire.HeaderSessionID),
			// 🔴 The CONVERSATION key, from the existing config-driven
			// fingerprint table under `protocol: mcp` — 🚫 not a second
			// extraction mechanism, and 🚫 never guessed. Empty for Claude
			// Code, which sends neither convention header; see the yaml.
			ConversationSessionID: sessionid.Default().Extract(r, MCPSessionProtocol, ""),
			AppSlug:               h.appSlugFor(r),
			Origin:                originFor(r),
			ArgsDigest:            mcpwire.MarshalArgsDigest(nil),
			CreatedAtMs:           now.UnixMilli(),
		},
	}
}

func (h *Handler) mintCallID(r *http.Request) string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		h.logger.WarnContext(r.Context(), "MCP call id could not be minted from crypto/rand; "+
			"falling back to a timestamp id. The record is still written — a missing audit row is "+
			"worse than a guessable primary key, which this is not used as.",
			"event.name", observability.EventProxyMCPCallIDFallback, "error", err)
		return "call-" + itoa64(time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// appSlugFor answers WHICH AGENT made this call.
//
// 🔴 Read straight off the inbound request, at the top of the handler, using the
// EXISTING uaattribution word list — 🚫 not a second vocabulary. The rule that
// matters is WHERE: on the LLM plane the OAuth injector rewrites User-Agent to
// `claude-cli/...` before forwarding, so an attribution taken after it would
// report every client as claude-code AND LOOK ENTIRELY NORMAL doing it (task
// 7.5a1). The MCP plane has no such middleware today; taking the value at
// ingress is what keeps that true if one is ever added.
//
// 🔴 The result is NEVER empty. An unrecognised client is `unknown-app`, which
// is a VERDICT ("we looked and did not recognise it"), not a gap. It must not be
// confused with the conversation-audit "attribution pending" state, which means
// a second reporting channel has not arrived yet and WILL change (task 7.5a2).
// No such pending state exists on this record: the User-Agent is in hand at the
// moment the row is built.
func (h *Handler) appSlugFor(r *http.Request) string {
	return uaattribution.Default().MatchOrLog(r.Header.Get("User-Agent"), h.logger)
}

// originFor separates a real Agent call from the console's "try it" panel.
//
// 🔴 The console test is a VALUE here, never a bypass: it runs as the operator's
// own seat through this same endpoint, and is authorised, validated, recorded
// and (once P0b exists) rate-limited exactly like any other call. The header is
// read only to LABEL the row — nothing in the gateway branches on it, and
// nothing may learn to (R23 / fence 8.F5).
func originFor(r *http.Request) string {
	if r.Header.Get(ConsoleTestHeader) != "" {
		return mcpwire.OriginConsoleTest
	}
	return mcpwire.OriginAgent
}

// MCPSessionProtocol is this plane's key in session-fingerprint.yaml.
//
// 🔴 A constant, so the Go side and the yaml cannot drift by a typo. A protocol
// name that matches no rule falls through to common_fallback and still returns
// a value, which means the drift would be INVISIBLE — the extraction keeps
// working, just not by the rule anybody wrote.
const MCPSessionProtocol = "mcp"

// ConsoleTestHeader labels a call made from the console's test panel.
//
// 🔴 An `X-Aikey-*` header on the INBOUND side only. It is stripped, like every
// other internal header, before anything goes upstream (D-13) — the rule
// forbids sending them to a backend, not receiving them from our own console.
const ConsoleTestHeader = "X-Aikey-Mcp-Origin-Console-Test"

// noteOutcome implements outcomeSink.
func (c *callRecorder) noteOutcome(code mcpwire.ErrorCode, isError bool) {
	if c.noted {
		return
	}
	c.noted, c.code, c.isError = true, code, isError
}

// tool records which tool the call resolved to, and the published fingerprint
// it was served under. Called once authorisation has answered.
//
// 🔴 ManifestHash is the PUBLISHED hash from the policy, not one recomputed
// here: the record's job is to prove what ran matched what a human approved, and
// a hash computed at call time would only prove the gateway agrees with itself.
func (c *callRecorder) tool(t PolicyTool, toolsetID string) {
	c.rec.ToolID = t.ID
	c.rec.ToolName = t.Name
	c.rec.BackendID = t.BackendID
	c.rec.ManifestHash = t.ManifestHash
	c.rec.VirtualServerID = toolsetID
}

// arguments records the structural digest of the call's arguments.
//
// 🔴 The digest, always. Raw arguments are a separate, org-gated decision made
// downstream (task 7.2); this function has no path that stores a value.
func (c *callRecorder) arguments(args json.RawMessage) {
	c.rec.ArgsDigest = mcpwire.MarshalArgsDigest(mcpwire.DigestArgs(args))
}

// retainRaw stores the raw arguments — the ONLY code path in this product that
// does, and it is gated three ways.
//
// 🔴 The three gates, and why each one is load-bearing:
//
//	the ORG switched it on   default off; the default is the security property,
//	                         not a convenience. Absent policy ⇒ off.
//	DLP actually RAN         a degraded filter means nothing was scanned. Storing
//	                         "post-DLP" arguments that no DLP ever saw would be a
//	                         lie told by the field name itself.
//	the payload was CLEARED   what is stored is the payload AFTER masking, never
//	                         the original. Storing the original would make the
//	                         mask cosmetic — the value would be redacted on the
//	                         wire and kept verbatim in our database.
//
// 🔴 A truncated scan does NOT qualify either: only part of the value was
// examined, so "this cleared DLP" is not something we know about the rest.
func (c *callRecorder) retainRaw(scanned json.RawMessage, verdict ComplianceVerdict, enabled bool) {
	if !enabled || verdict.Degraded || verdict.Truncated {
		return
	}
	raw := string(scanned)
	c.rec.ArgsRaw = &raw
}

// finish writes the record. Called from a defer, so it runs on every path out
// of the handler including a panic unwind.
func (c *callRecorder) finish(h *Handler, r *http.Request) {
	c.rec.DurationMs = time.Since(c.started).Milliseconds()
	c.rec.Status = c.status(h, r)
	h.observeCall(c.rec)
	if h.calls == nil {
		// 🔴 No sink is a real configuration (a build with no local store), not
		// an error to shout about on every call — but it must not be invisible
		// either, or "why is the call log empty" becomes unanswerable. Debug
		// here; the ABSENCE of a sink is reported once, loudly, at wiring time,
		// and shows up in /health/mcp as call_recording:"off".
		h.logger.DebugContext(r.Context(), "MCP call not recorded: no call sink is wired on this node",
			"tool", c.rec.ToolName)
		return
	}
	h.calls.RecordCall(r.Context(), c.rec)
}

// status turns the stamped answer into the recorded status.
func (c *callRecorder) status(h *Handler, r *http.Request) string {
	if !c.noted {
		// 🔴 Nothing answered. That is a defect in this gateway — a branch that
		// returned without writing — and it is recorded as one rather than
		// guessed at. ERROR, not WARN: the client is hanging.
		h.logger.ErrorContext(r.Context(),
			"MCP tools/call ended without writing a JSON-RPC answer; recorded as internal_error",
			"event.name", observability.EventProxyMCPCallUnanswered,
			"tool", c.rec.ToolName, "call_id", c.rec.CallID)
		return mcpwire.CallStatusInternalError
	}
	if !c.isError {
		return mcpwire.CallStatusOK
	}
	if status, ok := mcpwire.CallStatusForErrorCode(c.code); ok {
		c.rec.ErrorCode = string(c.code)
		return status
	}
	// 🔴 An error this build cannot classify. It is NOT filed under an existing
	// status — that would hide a new refusal shape among the known ones. The
	// code itself is kept so the row still says what happened.
	//
	// The empty code is the internal-error writer (writeInternalError carries no
	// frozen code, on purpose: a panic is our defect, not the upstream's), which
	// is exactly what internal_error means. A NON-empty unclassified code is a
	// different animal and warrants the WARN.
	if c.code != "" {
		h.logger.WarnContext(r.Context(),
			"MCP tools/call answered with an error code this build cannot classify into a call status; "+
				"recorded as internal_error with the code preserved",
			"event.name", observability.EventProxyMCPCallStatusUnclassified,
			"error_code", string(c.code), "tool", c.rec.ToolName)
		c.rec.ErrorCode = string(c.code)
	}
	return mcpwire.CallStatusInternalError
}

// observeCall feeds the in-memory counters behind /metrics and /health/mcp.
func (h *Handler) observeCall(rec mcpwire.CallRecord) {
	if h.callStats == nil {
		return
	}
	h.callStats.Observe(rec)
}

// itoa64 keeps strconv out of the hot file for one call site.
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
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

// toolsetIDFor resolves the virtual server's id for the record.
//
// Empty when the catalog cannot answer. 🔴 Fail-quiet on purpose: a missing id
// makes one report column less specific, while refusing the call over a
// bookkeeping lookup would take a working tool offline.
func (h *Handler) toolsetIDFor(ctx context.Context, slug string) string {
	ident, ok := h.catalog.(ToolsetIdentifier)
	if !ok {
		return ""
	}
	id, found := ident.ToolsetID(ctx, slug)
	if !found {
		return ""
	}
	return id
}
