package mcp

// The Streamable HTTP handshake.
//
// # What was wrong
//
// httpTransport sent `tools/list` (and `tools/call`) cold — no `initialize`, no
// `notifications/initialized`, no session header. MCP's Streamable HTTP
// transport is a session protocol and a compliant server refuses everything
// until the handshake completes. Measured against the reference server
// (`server-everything`, 2026-09-07):
//
//	POST /mcp {"method":"tools/list"}
//	→ HTTP 400 {"code":-32000,"message":"Bad Request: Server not initialized"}
//
// The consequences were not limited to one feature. The manifest prober's only
// probe IS tools/list, so every backend stayed `unknown` forever, no tool was
// ever discovered, `mcp_tool` stayed empty and `manifest_synced_at_ms` stayed 0
// — while the policy rail looked perfectly healthy, because it never talks to
// the backend. Tool CALLS went down the same path and would have failed the
// same way.
//
// 🔴 The stdio transport did this correctly from the start (stdio.go:handshake).
// One transport implementing a mandatory protocol step and the other skipping it
// is the shape to watch for here: the two are interchangeable to every caller
// above them, so the gap is invisible until a real backend is on the other end.
//
// Bug: workflow/CI/bugfix/20260907-mcp-http-transport-never-initialized.md

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// rpc performs one JSON-RPC request, establishing the MCP session first and
// re-establishing it once if the server says it is gone.
func (t *httpTransport) rpc(ctx context.Context, b UpstreamBackend, method string, params json.RawMessage) (*mcpwire.Envelope, error) {
	sess := t.sessionFor(b)

	id, err := t.establish(ctx, sess, b)
	if err != nil {
		return nil, err
	}

	env, _, err := t.roundTrip(ctx, b, method, params, id, false)
	if err == nil || !sessionGone(err) {
		return env, err
	}

	// 🔴 Exactly one retry, and only for a session the SERVER says it no longer
	// has. Sessions expire (the spec has the server drop them at will), and
	// without this every backend would need a proxy restart to recover from an
	// upstream restart. Looping instead of retrying once would turn a backend
	// that always answers "no session" into an infinite request storm against
	// somebody else's server.
	sess.mu.Lock()
	sess.established = false
	sess.id = ""
	sess.mu.Unlock()

	id, err2 := t.establish(ctx, sess, b)
	if err2 != nil {
		return nil, err2
	}
	env, _, err = t.roundTrip(ctx, b, method, params, id, false)
	return env, err
}

// establish returns the session id, performing the handshake if needed.
//
// The session's own mutex is held across the handshake so a burst of concurrent
// calls to a cold backend performs ONE handshake, not one per caller.
func (t *httpTransport) establish(ctx context.Context, sess *httpSession, b UpstreamBackend) (string, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.established {
		return sess.id, nil
	}

	params, err := json.Marshal(mcpwire.InitializeRequest{
		// 🔴 We offer OUR newest supported revision and accept what the backend
		// answers with — the version is negotiated, never compiled in as "the
		// latest". Same rule the stdio transport and the client-facing side (R1)
		// follow, and the same literal, so the three cannot drift.
		ProtocolVersion: mcpwire.SupportedProtocolVersions[0],
		ClientInfo:      mcpwire.Implementation{Name: "aikey-gateway", Version: "1"},
	})
	if err != nil {
		return "", err
	}

	env, hdr, err := t.roundTrip(ctx, b, mcpwire.MethodInitialize, params, "", false)
	if err != nil {
		return "", err
	}
	if env == nil {
		return "", &UpstreamError{Code: mcpwire.ErrBackendUnavailable,
			Detail: "backend answered the MCP handshake with no response"}
	}
	if env.Error != nil {
		return "", &UpstreamError{Code: mcpwire.ErrBackendUnavailable,
			Detail: fmt.Sprintf("backend refused initialize: %s", env.Error.Message)}
	}

	// 🔴 An EMPTY session id is a valid answer, not a failure: a stateless server
	// completes the handshake and assigns nothing. `established` is what records
	// that the handshake happened, so the two cases stay distinguishable.
	id := hdr.Get("Mcp-Session-Id")

	// The spec requires this notification before any other request. A server that
	// tracks it will keep refusing requests without it, which looks exactly like
	// the bug this file fixes.
	if _, _, err := t.roundTrip(ctx, b, mcpwire.MethodInitialized, nil, id, true); err != nil {
		return "", err
	}

	sess.id = id
	sess.established = true
	return id, nil
}

// sessionGone reports whether err is the server telling us our session is not
// one it recognises.
//
// 🔴 Deliberately narrow. Per the spec a server answers 404 for an expired
// session; the reference server answers 400 "Server not initialized" when it has
// no session for the request at all. Both mean "handshake again". Every OTHER
// 4xx — a bad request we built, a refused tool — must NOT trigger a re-handshake,
// or a permanent client-side error becomes two requests instead of one, forever.
func sessionGone(err error) bool {
	var ue *UpstreamError
	if !errors.As(err, &ue) {
		return false
	}
	return ue.Status == http.StatusNotFound || ue.Status == http.StatusBadRequest
}
