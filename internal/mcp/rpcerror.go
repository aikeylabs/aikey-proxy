package mcp

// rpcerror.go — turning a failure into something BOTH a generic MCP client and
// a human support flow can act on.
//
// # The two-audience problem
//
// A generic MCP client (Claude Desktop, mcp-inspector) switches on the JSON-RPC
// numeric code. Our console, our runbooks and the customer's alerting switch on
// the frozen string code (mcpwire.ErrorCode). Emitting only one of them serves
// one audience and abandons the other, so every error carries both:
//
//	{"jsonrpc":"2.0","id":7,"error":{
//	   "code": -32600,                       ← generic clients read this
//	   "message": "…human sentence…",
//	   "data": {"aikey_code":"MCP_TOOL_FORBIDDEN", …}   ← we read this
//	}}
//
// # 🔴 Why some errors are HTTP status codes and some are 200 + error body
//
// Both, deliberately, and the split is the MCP spec's, not ours:
//
//	before we have a valid JSON-RPC request   → HTTP status (401, 400, 429…)
//	                                            There is no id to answer, so an
//	                                            RPC-shaped reply would be a
//	                                            response to nothing.
//	after we have one                         → HTTP 200 + JSON-RPC error
//	                                            The request WAS delivered and
//	                                            processed; the failure is a
//	                                            result, and clients correlate it
//	                                            by id.
//
// Getting this backwards is a real interop bug: a client that receives HTTP 403
// for a tools/call it sent with id=7 has no way to fail that particular call,
// and typically tears down the whole session instead.
//
// # 🔴 Messages must be actionable
//
// Project rule: every error carries a cause AND a next step. "Forbidden" is not
// an error message; "this seat is not granted `create_issue`; ask an admin to
// add it in Keys → MCP grants" is.

import (
	"encoding/json"
	"net/http"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// errorData is the structured payload carried in RPCError.Data.
//
// Upstream is present so the reader does not have to know that EXT_ is a
// prefix convention — the flag says outright whose fault this is, which is the
// single most expensive question in supporting a gateway product.
type errorData struct {
	AiKeyCode string `json:"aikey_code"`
	Upstream  bool   `json:"upstream"`
	// SupportedVersions is populated only for MCP_PROTOCOL_UNSUPPORTED. Without
	// it the client knows it failed but has nothing to try next.
	SupportedVersions []string `json:"supported_protocol_versions,omitempty"`
	// RetryAfterSeconds is populated for backend cooldown / rate limiting.
	// "Try again later" without a number is not actionable.
	RetryAfterSeconds int `json:"retry_after_seconds,omitempty"`
	// FieldPath is populated for MCP_SCHEMA_INVALID: which argument was wrong.
	FieldPath string `json:"field_path,omitempty"`
}

// rpcError builds the JSON-RPC error object for a frozen AiKey code.
func rpcError(code mcpwire.ErrorCode, message string, extra *errorData) *mcpwire.RPCError {
	d := errorData{AiKeyCode: string(code), Upstream: mcpwire.IsUpstream(code)}
	if extra != nil {
		d.SupportedVersions = extra.SupportedVersions
		d.RetryAfterSeconds = extra.RetryAfterSeconds
		d.FieldPath = extra.FieldPath
	}
	raw, err := json.Marshal(d)
	if err != nil {
		// Marshalling a struct of strings and ints cannot fail; if it somehow
		// did, an error with no data still beats no error at all.
		raw = nil
	}
	return &mcpwire.RPCError{
		Code:    mcpwire.RPCCodeFor(code),
		Message: message,
		Data:    raw,
	}
}

// writeRPCResult writes a successful JSON-RPC response echoing id.
func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	raw, err := json.Marshal(result)
	if err != nil {
		writeInternalError(w, id, "The MCP gateway could not encode its response.")
		return
	}
	// 🔴 Stamped here, not at the call site: this is the funnel every success
	// must pass through, so the call record cannot be forgotten by a new branch.
	noteOutcome(w, "", false)
	writeJSON(w, http.StatusOK, mcpwire.Envelope{
		JSONRPC: mcpwire.JSONRPCVersion,
		ID:      id,
		Result:  raw,
	})
}

// writeRPCError writes HTTP 200 with a JSON-RPC error, for failures that occur
// AFTER a valid request with an id was parsed. See the header comment for why
// this is 200 and not the code's HTTP status.
func writeRPCError(w http.ResponseWriter, id json.RawMessage, code mcpwire.ErrorCode, message string, extra *errorData) {
	noteOutcome(w, code, true)
	writeJSON(w, http.StatusOK, mcpwire.Envelope{
		JSONRPC: mcpwire.JSONRPCVersion,
		ID:      id,
		Error:   rpcError(code, message, extra),
	})
}

// writeRPCHTTPError writes the frozen code's HTTP status together with the same
// JSON-RPC error body, for failures that occur BEFORE a usable id exists
// (transport-level rejections: auth, saturation, malformed body).
//
// The body is still JSON-RPC shaped even though there is no id to echo, so a
// client that parses bodies uniformly does not need a second code path.
func writeRPCHTTPError(w http.ResponseWriter, id json.RawMessage, code mcpwire.ErrorCode, message string, extra *errorData) {
	noteOutcome(w, code, true)
	status := mcpwire.HTTPStatusFor(code)
	if status == http.StatusTooManyRequests && extra != nil && extra.RetryAfterSeconds > 0 {
		// Standard header so generic HTTP clients back off correctly without
		// understanding our body at all.
		w.Header().Set("Retry-After", itoa(extra.RetryAfterSeconds))
	}
	writeJSON(w, status, mcpwire.Envelope{
		JSONRPC: mcpwire.JSONRPCVersion,
		ID:      id,
		Error:   rpcError(code, message, extra),
	})
}

// writeInternalError reports a fault inside AiKey itself.
//
// 🔴 It carries NO frozen MCP_* code, on purpose. The ten frozen codes describe
// BUSINESS outcomes (forbidden, rate limited, upstream down) that a customer
// can act on. A panic or an encoding failure is our defect, and dressing it up
// as one of those would send the customer looking through their own grants or
// their own backend for a problem that is ours. JSON-RPC's own -32603
// "Internal error" is the honest vocabulary, and 🚫 it must never be an EXT_
// code — that would blame the upstream for our bug.
func writeInternalError(w http.ResponseWriter, id json.RawMessage, message string) {
	// 🔴 The empty code IS the signal: no frozen code means "our defect", which
	// is what internal_error records. See callRecorder.status.
	noteOutcome(w, "", true)
	writeJSON(w, http.StatusInternalServerError, mcpwire.Envelope{
		JSONRPC: mcpwire.JSONRPCVersion,
		ID:      id,
		Error: &mcpwire.RPCError{
			Code:    mcpwire.CodeInternalError,
			Message: message,
		},
	})
}

// writeParseError reports a body that is not JSON-RPC at all.
func writeParseError(w http.ResponseWriter, message string) {
	noteOutcome(w, "", true)
	writeJSON(w, http.StatusBadRequest, mcpwire.Envelope{
		JSONRPC: mcpwire.JSONRPCVersion,
		Error: &mcpwire.RPCError{
			Code:    mcpwire.CodeParseError,
			Message: message,
		},
	})
}

// writeMethodNotFound reports an MCP method this gateway does not implement.
//
// The message names what IS implemented rather than only what is not: a client
// author debugging against us should not have to guess the supported set.
func writeMethodNotFound(w http.ResponseWriter, id json.RawMessage, method string) {
	noteOutcome(w, "", true)
	writeJSON(w, http.StatusOK, mcpwire.Envelope{
		JSONRPC: mcpwire.JSONRPCVersion,
		ID:      id,
		Error: &mcpwire.RPCError{
			Code: mcpwire.CodeMethodNotFound,
			Message: "Method " + method + " is not implemented by the AiKey MCP gateway. " +
				"Supported: initialize, tools/list, tools/call, ping.",
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// itoa avoids pulling strconv in for one call site while keeping the intent
// obvious at the point of use.
func itoa(n int) string {
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

// mcpJSONError builds a bare JSON-RPC error envelope with no id, for
// transport-level refusals that happen before any request was parsed.
func mcpJSONError(message string) mcpwire.Envelope {
	return mcpwire.Envelope{
		JSONRPC: mcpwire.JSONRPCVersion,
		Error:   &mcpwire.RPCError{Code: mcpwire.CodeInvalidRequest, Message: message},
	}
}

// writeRPCHTTPErrorInBand writes HTTP 200 with a JSON-RPC error that also
// carries the standard Retry-After header.
//
// 🔴 The odd shape is deliberate. The failure happened AFTER a valid request
// with an id, so the body must be a JSON-RPC error at HTTP 200 (otherwise the
// client cannot fail that specific call and typically tears down the whole
// session). But a rate-limit or cooldown answer is also useful to generic HTTP
// machinery, which reads Retry-After and knows nothing about our body. Emitting
// both serves both audiences without lying to either.
func writeRPCHTTPErrorInBand(w http.ResponseWriter, id json.RawMessage, code mcpwire.ErrorCode, message string, extra *errorData) {
	noteOutcome(w, code, true)
	if extra != nil && extra.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", itoa(extra.RetryAfterSeconds))
	}
	writeJSON(w, http.StatusOK, mcpwire.Envelope{
		JSONRPC: mcpwire.JSONRPCVersion,
		ID:      id,
		Error:   rpcError(code, message, extra),
	})
}
