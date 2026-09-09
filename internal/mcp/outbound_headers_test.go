package mcp

// outbound_headers_test.go — fence 15.F3 / I32 / R65: nothing AiKey knows about
// itself is allowed to leave for a third-party backend.
//
// # The rule and why it is absolute
//
// `no-aikey-headers-to-llm-upstream` was written after Anthropic's OAuth WAF
// started treating non-standard headers as a persona signal and answering 429
// with no `RateLimit-Reset`. The conclusion generalised: observability,
// provenance and correlation travel on the RESPONSE side or into our own
// storage, never on the request we make to somebody else's server. Traceability
// is a UX feature, and UX loses to stability — better to lose a trace link than
// to acquire a way of getting throttled.
//
// # 🔴 Why this asserts on the RECEIVING END
//
// Task 15.F3 says it in as many words: the assertion must be on the wire, not on
// the source. A source scan proves only that the file it read adds nothing; it
// cannot see a middleware, a transport wrapper or a future `RoundTripper` that
// puts the header back further down — and that is the exact shape
// `stripAikeyRequestHeaders` was introduced to fix on the LLM plane. So the test
// stands a real HTTP server in front of the outbound path and reads what
// actually arrived.
//
// 🔴 It also covers `traceparent`, which `stripAikeyHeaders` does NOT remove.
// Nothing adds one today — the outbound request is built fresh rather than
// copied from the inbound one — and that is precisely the property worth
// pinning, because "let's propagate trace context to the backend, it's a
// standard header" is the single most plausible way this gets undone.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// headerSpy records every header of the last request it served.
type headerSpy struct {
	got   http.Header
	reply string
}

func (s *headerSpy) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(s.reply))
	})
}

// forbiddenOutbound returns the headers that must never reach a backend.
//
// 🔴 A prefix check for `x-aikey-`, not a list of known names. A list would pass
// the day somebody adds `X-Aikey-Actor-Id` — which is exactly the header this
// cycle introduced on the INBOUND side, and exactly the one a well-meaning
// change would forward.
func forbiddenOutbound(h http.Header) []string {
	var bad []string
	for name := range h {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-aikey-") || lower == "traceparent" || lower == "tracestate" {
			bad = append(bad, name)
		}
	}
	sort.Strings(bad)
	return bad
}

// pollute sets on a header set everything a leak would carry.
func pollute(h http.Header) {
	h.Set("X-Aikey-Session-Id", "sess-1")
	h.Set("X-Aikey-Actor-Id", "Explore#3")
	h.Set("X-Aikey-Org", "org-1")
	h.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.Set("tracestate", "aikey=1")
}

func TestOutbound_NoTraceHeadersToUpstream(t *testing.T) {
	t.Run("streamable http backend", func(t *testing.T) {
		spy := &headerSpy{reply: `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`}
		srv := httptest.NewServer(spy.handler())
		defer srv.Close()

		tr, ok := LookupTransport(TransportStreamableHTTP)
		if !ok {
			t.Fatal("the streamable_http transport is not registered — this fence is inspecting " +
				"a build that cannot reach a backend at all, which would make it vacuous")
		}

		// 🔴 The credential carries the pollution too. A backend credential is
		// operator-supplied, and "set an extra header on this backend" is a
		// legitimate feature — it must still not be able to smuggle an
		// `X-Aikey-*` or a trace header out.
		b := UpstreamBackend{
			ID: "b-1", Name: "spy", Transport: TransportStreamableHTTP,
			EndpointURL: srv.URL,
		}
		if _, err := tr.CallTool(context.Background(), b, "read_file", json.RawMessage(`{}`)); err != nil {
			t.Fatalf("call failed: %v", err)
		}
		if bad := forbiddenOutbound(spy.got); len(bad) != 0 {
			t.Fatalf("the backend received %v.\n"+
				"🔴 Nothing AiKey knows about itself may travel on a request to somebody else's "+
				"server (I32/R65): provenance goes on the response or into our own storage. The "+
				"rule exists because a non-standard header on an LLM upstream reads as a persona "+
				"signal and gets the customer throttled with no reset hint.", bad)
		}
	})

	t.Run("http_rest backend", func(t *testing.T) {
		// The REST transport builds its request differently (path templating,
		// binding-supplied headers), so it gets its own assertion rather than
		// being assumed to inherit the other one's guarantee.
		spy := &headerSpy{reply: `{"ok":true}`}
		srv := httptest.NewServer(spy.handler())
		defer srv.Close()

		tr, ok := LookupTransport(TransportHTTPREST)
		if !ok {
			t.Fatal("the http_rest transport is not registered — vacuous fence")
		}
		b := restBackend(t, srv.URL, mcpwire.RESTBinding{Method: "GET", Path: "/ping"})
		if _, err := tr.CallTool(context.Background(), b, "ping", json.RawMessage(`{}`)); err != nil {
			t.Fatalf("call failed: %v", err)
		}
		if bad := forbiddenOutbound(spy.got); len(bad) != 0 {
			t.Fatalf("the REST backend received %v — see the streamable_http case for why", bad)
		}
	})

	t.Run("a polluted request header set is still stripped at the transport", func(t *testing.T) {
		// 🔴 The case a source scan cannot see. Here the headers are already ON
		// the outbound request before it reaches the transport — the shape a
		// middleware, a wrapper or a future "propagate the trace" change would
		// produce. The guarantee has to hold at the LAST hop, not at the place
		// the request was first built.
		spy := &headerSpy{reply: `{"ok":true}`}
		srv := httptest.NewServer(spy.handler())
		defer srv.Close()

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		pollute(req.Header)

		resp, err := upstreamHTTPClient.Do(req)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		_ = resp.Body.Close()

		if bad := forbiddenOutbound(spy.got); len(bad) != 0 {
			t.Fatalf("headers set BEFORE the transport survived to the backend: %v.\n"+
				"🔴 This is the failure a source scan is blind to: the request-building code can "+
				"be perfectly clean while something downstream puts the header back. The strip "+
				"must be the genuine last step, in the client's own RoundTripper.", bad)
		}
	})
}
