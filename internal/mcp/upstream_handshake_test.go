package mcp

// Fence: the Streamable HTTP transport performs the MCP handshake.
//
// # What went wrong
//
// httpTransport sent tools/list and tools/call cold — no `initialize`, no
// `notifications/initialized`, no session header. Streamable HTTP is a session
// protocol and a compliant server refuses everything until the handshake
// completes. Measured against the reference server on 2026-09-07:
//
//	POST /mcp {"method":"tools/list"}
//	→ HTTP 400 {"code":-32000,"message":"Bad Request: Server not initialized"}
//
// Nothing in the suite noticed, because every existing HTTP-transport test used
// a stub that answered any method it was handed. A fake that is more permissive
// than the protocol makes a client that does not speak the protocol look
// correct — which is why the server below REFUSES like the real one instead of
// simply replying.
//
// Bug: workflow/CI/bugfix/20260907-mcp-http-transport-never-initialized.md

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// specServer is a Streamable HTTP server that enforces the session rules the
// real one enforces: nothing but `initialize` is answered without a valid
// session, and tools/list is refused until the initialized notification lands.
type specServer struct {
	mu sync.Mutex
	// handshakes counts completed initialize calls — the session-reuse assertion.
	handshakes  int
	initialized map[string]bool
	// dropNext makes the next session lookup fail, simulating expiry.
	dropNext bool
	// stateless serves a server that assigns no session id at all.
	stateless bool
	methods   []string
	// sawIDOnNotification records the spec violation of giving a notification an id.
	sawIDOnNotification bool
}

func (s *specServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env mcpwire.Envelope
		_ = json.NewDecoder(r.Body).Decode(&env)

		s.mu.Lock()
		s.methods = append(s.methods, env.Method)
		if env.Method == mcpwire.MethodInitialized && len(env.ID) > 0 {
			s.sawIDOnNotification = true
		}
		s.mu.Unlock()

		write := func(result any) {
			w.Header().Set("Content-Type", "application/json")
			body, _ := json.Marshal(result)
			_ = json.NewEncoder(w).Encode(mcpwire.Envelope{
				JSONRPC: mcpwire.JSONRPCVersion,
				ID:      json.RawMessage(`1`),
				Result:  body,
			})
		}
		refuse := func(code int, msg string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(mcpwire.Envelope{
				JSONRPC: mcpwire.JSONRPCVersion,
				Error:   &mcpwire.RPCError{Code: -32000, Message: msg},
			})
		}

		if env.Method == mcpwire.MethodInitialize {
			s.mu.Lock()
			s.handshakes++
			sid := ""
			if !s.stateless {
				sid = "sess-" + string(rune('a'+s.handshakes-1))
				s.initialized[sid] = false
			}
			s.mu.Unlock()
			if sid != "" {
				w.Header().Set("Mcp-Session-Id", sid)
			}
			write(mcpwire.InitializeResult{
				ProtocolVersion: mcpwire.SupportedProtocolVersions[0],
				ServerInfo:      mcpwire.Implementation{Name: "spec-server", Version: "1"},
			})
			return
		}

		sid := r.Header.Get("Mcp-Session-Id")
		s.mu.Lock()
		drop := s.dropNext
		if drop {
			s.dropNext = false
		}
		_, known := s.initialized[sid]
		stateless := s.stateless
		s.mu.Unlock()

		if drop {
			// The spec's expiry answer.
			refuse(http.StatusNotFound, "Session not found")
			return
		}
		if !stateless && !known {
			// The reference server's answer to a cold request.
			refuse(http.StatusBadRequest, "Bad Request: Server not initialized")
			return
		}

		if env.Method == mcpwire.MethodInitialized {
			s.mu.Lock()
			if !stateless {
				s.initialized[sid] = true
			}
			s.mu.Unlock()
			w.WriteHeader(http.StatusAccepted) // 202, empty body — the spec's ack.
			return
		}

		if !stateless {
			s.mu.Lock()
			ready := s.initialized[sid]
			s.mu.Unlock()
			if !ready {
				refuse(http.StatusBadRequest, "Bad Request: Server not initialized")
				return
			}
		}

		if env.Method == mcpwire.MethodToolsList {
			write(mcpwire.ListToolsResult{Tools: []mcpwire.Tool{{Name: "echo"}, {Name: "add"}}})
			return
		}
		refuse(http.StatusBadRequest, "unexpected method "+env.Method)
	})
}

func newSpecServer(t *testing.T) (*specServer, string) {
	t.Helper()
	s := &specServer{initialized: map[string]bool{}}
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return s, srv.URL
}

func httpBackend(url string) UpstreamBackend {
	return UpstreamBackend{ID: "b1", Name: "spec", Transport: TransportStreamableHTTP, EndpointURL: url}
}

// 🔴 The defect itself: against a server that enforces the protocol, a transport
// that skips the handshake gets HTTP 400 and discovers nothing.
func TestHTTPTransport_HandshakesBeforeListingTools(t *testing.T) {
	spec, url := newSpecServer(t)
	tr := &httpTransport{name: TransportStreamableHTTP}

	tools, err := tr.ListTools(t.Context(), httpBackend(url))
	if err != nil {
		t.Fatalf("ListTools against a spec-compliant server: %v\n"+
			"This is the 20260907 defect: the transport sent tools/list without initialize.", err)
	}
	if len(tools) != 2 {
		t.Fatalf("tools = %d, want 2", len(tools))
	}

	spec.mu.Lock()
	defer spec.mu.Unlock()
	if spec.handshakes != 1 {
		t.Fatalf("handshakes = %d, want 1", spec.handshakes)
	}

	// 🔴 ORDER, not merely presence. The spec's requirement is that nothing
	// precedes the handshake, and asserting only "a handshake happened" is
	// satisfied by the broken shape too: send tools/list cold, eat the 400, then
	// handshake and retry. That recovers — and it also means every single call
	// costs an extra failed round trip against somebody else's server, and that a
	// backend which answers 400 for its OWN reasons is retried forever. This
	// assertion is what makes removing the handshake go red; without it the
	// session-recovery path silently rescues the defect and the fence reads green.
	if len(spec.methods) < 3 {
		t.Fatalf("methods = %v, want initialize, notifications/initialized, tools/list", spec.methods)
	}
	if spec.methods[0] != mcpwire.MethodInitialize {
		t.Fatalf("the first thing sent to the backend was %q, not %q — the handshake must PRECEDE "+
			"every other request, not repair a failure after one", spec.methods[0], mcpwire.MethodInitialize)
	}
	if spec.methods[1] != mcpwire.MethodInitialized {
		t.Fatalf("methods[1] = %q, want %q — the spec requires the notification before any request",
			spec.methods[1], mcpwire.MethodInitialized)
	}
	if spec.methods[2] != mcpwire.MethodToolsList {
		t.Fatalf("methods[2] = %q, want %q", spec.methods[2], mcpwire.MethodToolsList)
	}
	// 🔴 A notification with an id is a REQUEST. Servers may answer it, or leave
	// the caller waiting for a reply the spec says never comes.
	if spec.sawIDOnNotification {
		t.Error("notifications/initialized carried a JSON-RPC id; a notification must not have one")
	}
}

// The session is REUSED. A handshake per call is two extra round trips every
// time and leaks a session per request on servers that track them.
func TestHTTPTransport_ReusesTheSessionAcrossCalls(t *testing.T) {
	spec, url := newSpecServer(t)
	tr := &httpTransport{name: TransportStreamableHTTP}
	b := httpBackend(url)

	for i := 0; i < 4; i++ {
		if _, err := tr.ListTools(t.Context(), b); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	spec.mu.Lock()
	defer spec.mu.Unlock()
	if spec.handshakes != 1 {
		t.Fatalf("handshakes = %d after 4 calls, want 1 — the session is not being reused", spec.handshakes)
	}
}

// A server may drop a session at any time. Without recovery, an upstream restart
// would need a proxy restart to clear.
func TestHTTPTransport_ReestablishesADroppedSession(t *testing.T) {
	spec, url := newSpecServer(t)
	tr := &httpTransport{name: TransportStreamableHTTP}
	b := httpBackend(url)

	if _, err := tr.ListTools(t.Context(), b); err != nil {
		t.Fatalf("first call: %v", err)
	}
	spec.mu.Lock()
	spec.dropNext = true
	spec.mu.Unlock()

	tools, err := tr.ListTools(t.Context(), b)
	if err != nil {
		t.Fatalf("call after the server dropped the session: %v — an upstream restart must not "+
			"require a proxy restart", err)
	}
	if len(tools) != 2 {
		t.Fatalf("tools = %d, want 2", len(tools))
	}
	spec.mu.Lock()
	defer spec.mu.Unlock()
	if spec.handshakes != 2 {
		t.Fatalf("handshakes = %d, want exactly 2 — one recovery, not a storm", spec.handshakes)
	}
}

// A stateless server completes the handshake and assigns no session id. An empty
// id must read as "handshake done, no session", never as "not handshaken" —
// otherwise every call re-handshakes forever.
func TestHTTPTransport_StatelessServerIsNotReHandshakenForever(t *testing.T) {
	spec, url := newSpecServer(t)
	spec.mu.Lock()
	spec.stateless = true
	spec.mu.Unlock()

	tr := &httpTransport{name: TransportStreamableHTTP}
	b := httpBackend(url)
	for i := 0; i < 3; i++ {
		if _, err := tr.ListTools(t.Context(), b); err != nil {
			t.Fatalf("call %d against a stateless server: %v", i, err)
		}
	}
	spec.mu.Lock()
	defer spec.mu.Unlock()
	if spec.handshakes != 1 {
		t.Fatalf("handshakes = %d, want 1 — an empty session id was mistaken for 'no handshake yet'",
			spec.handshakes)
	}
}
