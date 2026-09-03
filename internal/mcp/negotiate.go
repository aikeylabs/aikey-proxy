package mcp

// negotiate.go — protocol version negotiation (requirement R1).
//
// # What the spec actually mandates, and how R1 was corrected
//
// The MCP lifecycle spec is explicit:
//
//	"If the server supports the requested protocol version, it MUST respond
//	 with the same version. Otherwise, the server MUST respond with another
//	 protocol version it supports. This SHOULD be the latest version supported
//	 by the server. If the client does not support the version in the server's
//	 response, it SHOULD disconnect."
//	 — modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle
//
// R1 originally said the opposite: refuse with MCP_PROTOCOL_UNSUPPORTED and
// list the support set. That was implemented, tested, and then MEASURED against
// the real client — and it fails completely:
//
//	refusing            mcp-inspector: "error: ... does not implement 2025-11-25", zero tools
//	responding with ours mcp-inspector: handshake completes, tools listed
//
// 🔴 R1's underlying concern is still honoured. What R1 forbids is a SILENT
// downgrade — a client believing it got what it asked for and failing later on
// some unrelated call. That does not happen here, because the response CARRIES
// the version and the client is required by the same spec to compare it and
// disconnect if it cannot speak it. The negotiation is explicit on the wire; it
// is simply the CLIENT that adjudicates, not us.
//
// Corrected 2026-09-01 with the user's 拍板, after the measurement above.
// The correction is recorded in R1 and in the 0.14 freeze note.
//
// # Where MCP_PROTOCOL_UNSUPPORTED still lives
//
// The frozen error code is not orphaned by this change: the transport spec has
// its own, separate rule —
//
//	"If the server receives a request with an invalid or unsupported
//	 MCP-Protocol-Version, it MUST respond with 400 Bad Request."
//	 — .../basic/transports#protocol-version-header
//
// That is a POST-handshake, per-request check, and it is where the code is
// emitted. See CheckProtocolVersionHeader below.

import "github.com/AiKeyLabs/pkg/mcpwire"

// NegotiateResult is the outcome of one handshake.
type NegotiateResult struct {
	// Agreed is the revision both sides will use. Meaningful only when OK.
	Agreed mcpwire.ProtocolVersion
	// OK reports whether a revision was agreed. Always true today — the spec
	// leaves no failure path at handshake time — but kept in the shape so the
	// call sites read as negotiation rather than as an unconditional getter.
	OK bool
	// Downgraded reports that the client asked for a revision we do not
	// implement and was answered with ours instead.
	//
	// 🔴 Not an error, but not nothing either: a steadily rising Downgraded rate
	// is the signal that the client population has moved past this build. It is
	// logged rather than swallowed for exactly that reason.
	Downgraded bool
	// Requested echoes what the client asked for, for the error message and
	// for the log line.
	Requested mcpwire.ProtocolVersion
}

// Negotiate picks the revision to use.
//
// Rules, in order:
//
//  1. The client asked for something we support → use exactly that. We never
//     "upgrade" a client that pinned a version: it pinned it for a reason, and
//     answering with a newer revision than requested is how a client ends up
//     parsing fields it does not understand.
//  2. The client asked for nothing at all (empty) → use our newest. Some early
//     clients omit the field.
//  3. Anything else → 🔴 respond with our NEWEST supported revision, per the
//     spec MUST quoted in the file header. Downgraded is true so the caller can
//     log it: a version mismatch is not an error, but it IS a fact an operator
//     wants to see before a client population drifts away from us entirely.
func Negotiate(requested mcpwire.ProtocolVersion) NegotiateResult {
	if requested == "" || !mcpwire.IsSupported(requested) {
		return NegotiateResult{
			Agreed:     mcpwire.SupportedProtocolVersions[0],
			OK:         true,
			Downgraded: requested != "",
			Requested:  requested,
		}
	}
	return NegotiateResult{Agreed: requested, OK: true, Requested: requested}
}

// CheckProtocolVersionHeader validates the per-request MCP-Protocol-Version
// header that clients MUST send after initialization.
//
// Spec (transports § Protocol Version Header):
//
//   - absent → 🔴 the server SHOULD assume 2025-03-26. Not our newest: the
//     header was introduced later, so a client that omits it is by definition an
//     older one, and assuming our newest would attribute newer semantics to a
//     client that cannot have meant them.
//   - present and unsupported → the server MUST respond 400 Bad Request.
//
// Returns the effective version and whether it is acceptable.
func CheckProtocolVersionHeader(header string) (mcpwire.ProtocolVersion, bool) {
	if header == "" {
		return mcpwire.ProtocolV20250326, true
	}
	v := mcpwire.ProtocolVersion(header)
	return v, mcpwire.IsSupported(v)
}

// UnsupportedHeaderMessage is the human half of a rejected
// MCP-Protocol-Version header.
func UnsupportedHeaderMessage(requested mcpwire.ProtocolVersion) string {
	return "The MCP-Protocol-Version header names revision " + string(requested) +
		", which this gateway does not implement. Supported revisions are listed in " +
		"error.data.supported_protocol_versions; send one of them, or re-run initialize " +
		"and use the revision the gateway returns."
}
