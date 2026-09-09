package mcp

// origin.go — DNS-rebinding defence for the MCP endpoint.
//
// # The attack this closes
//
// The MCP transport spec makes this a MUST, and it is a MUST for a concrete
// reason:
//
//	"Servers MUST validate the Origin header on all incoming connections to
//	 prevent DNS rebinding attacks."
//	 — modelcontextprotocol.io/specification/2025-06-18/basic/transports
//
// Concretely: the gateway listens on 127.0.0.1. A web page the developer has
// open in their browser cannot normally talk to it — but with DNS rebinding, an
// attacker-controlled hostname first resolves to their own server (so the page
// loads) and then re-resolves to 127.0.0.1. The browser now considers requests
// to that hostname same-origin and sends them to the local gateway, carrying
// whatever ambient credentials the browser holds.
//
// 🔴 For THIS product that is not a generic web risk. The whole point of the
// gateway is that it holds the customer's GitHub PATs and database passwords so
// the developer's machine does not have to. A rebinding hole would let any web
// page the developer visits drive those credentials — reintroducing, through
// the browser, precisely the exposure the product exists to remove.
//
// # Why "no Origin header" is ALLOWED
//
// Browsers always attach Origin to cross-origin requests. Non-browser clients —
// Claude Desktop, Claude Code, mcp-inspector, curl — attach none. So:
//
//	absent Origin      → not a browser → allow
//	loopback Origin    → a local dev tool → allow
//	anything else      → 403
//
// 🔴 Rejecting absent-Origin requests would break every real MCP client while
// stopping no attack; accepting arbitrary Origins would leave the hole open.
// The asymmetry is the mitigation, not an oversight.
//
// 2025-11-25 clarifies the status code for a rejected Origin is 403 Forbidden;
// that is what this returns.

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// originAllowed reports whether the request's Origin may reach the MCP plane.
func originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// No Origin: not a browser. See the file header.
		return true
	}
	// "null" is what a browser sends from a sandboxed iframe or a file:// page.
	// 🔴 Deny it: it is unattributable, so it cannot be shown to be safe, and
	// a sandboxed frame is a plausible delivery vehicle for the attack above.
	if strings.EqualFold(origin, "null") {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// guardOrigin rejects a disallowed Origin and reports whether the caller should
// stop.
//
// The refusal is deliberately terse. 🔴 It must not explain which origins are
// accepted: the only party reading this message is either a legitimate local
// tool that will never see it, or an attacker's page probing what will get
// through. The operator-facing detail belongs in the log line, not the body.
func (h *Handler) guardOrigin(w http.ResponseWriter, r *http.Request) bool {
	if originAllowed(r) {
		return false
	}
	h.logger.WarnContext(r.Context(),
		"rejected an MCP request carrying a non-loopback Origin; this is the DNS-rebinding defence",
		"origin", r.Header.Get("Origin"),
		"path", r.URL.Path,
	)
	writeJSON(w, http.StatusForbidden, mcpJSONError(
		"Requests to the MCP endpoint from a browser origin are not accepted."))
	return true
}
