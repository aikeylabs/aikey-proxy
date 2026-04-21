package admin

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
)

// Tests for POST /admin/probe/ping.
//
// The handler has two paths:
//
//  1. Direct TCP dial to upstream (no upstream proxy configured).
//  2. HTTP HEAD through the configured upstream proxy.
//
// These tests hit path 1 against a controlled listener so they can't flake
// on the internet's mood. Path 2 is smoke-tested by setting HTTPS_PROXY to
// an obviously-broken value and asserting the handler reports the proxy
// dial failure instead of silently falling through to direct TCP (which
// would mask the misconfiguration in production).

func newHandlerForTest(cfg *config.Config) *Handler {
	// NewHandler normally takes a registry and event store; the ping handler
	// does not touch either, so nil is safe for these tests.
	return &Handler{
		cfg:       cfg,
		startedAt: time.Now(),
	}
}

func postProbePing(t *testing.T, h *Handler, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/probe/ping", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ProbePing(rr, req)
	return rr
}

func TestProbePing_DirectTCP_SucceedsAgainstLocalListener(t *testing.T) {
	// Spin up a throwaway listener on 127.0.0.1 so the handler has something
	// to TCP-connect to. Using a closed port would give a deterministic
	// "connection refused" — useful for the failure case below but not this
	// test, which wants OK.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	baseURL := "http://" + ln.Addr().String()

	h := newHandlerForTest(&config.Config{})
	rr := postProbePing(t, h, ProbePingRequest{BaseURL: baseURL})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	var resp ProbePingResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body = %q", err, rr.Body.String())
	}
	if !resp.OK {
		t.Errorf("expected ok=true, got ok=false, error=%q", resp.Error)
	}
	if resp.Host != "127.0.0.1" {
		t.Errorf("echoed host = %q, want 127.0.0.1", resp.Host)
	}
}

func TestProbePing_DirectTCP_FailsOnClosedPort(t *testing.T) {
	// A listener bound then immediately closed leaves the port *likely*
	// refused on macOS/Linux. Flakiness risk is low enough in CI that this
	// pins the "returns ok=false with a classifyNetError message" path.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	baseURL := "http://" + addr

	h := newHandlerForTest(&config.Config{})
	rr := postProbePing(t, h, ProbePingRequest{BaseURL: baseURL})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even on connect failure (so CLI can read structured error)",
			rr.Code)
	}
	var resp ProbePingResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.OK {
		t.Errorf("expected ok=false on closed port, got ok=true")
	}
	if resp.Error == "" {
		t.Errorf("expected non-empty error message when ok=false")
	}
}

func TestProbePing_UnknownProvider_WithoutBaseURL(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	rr := postProbePing(t, h, ProbePingRequest{Provider: "not-a-real-provider"})

	// We return 200 with ok=false so the CLI can parse the structured payload
	// uniformly. HTTP 400 is reserved for malformed bodies.
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp ProbePingResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.OK {
		t.Errorf("unknown provider should yield ok=false, got ok=true")
	}
	if resp.Error == "" {
		t.Errorf("expected error explaining the unknown provider")
	}
}

func TestProbePing_MissingProviderAndBaseURL(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	rr := postProbePing(t, h, ProbePingRequest{})
	// Empty request body is caller error → 400.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing provider+base_url", rr.Code)
	}
}

func TestProbePing_RespectsConfiguredUpstreamProxy(t *testing.T) {
	// When the proxy config declares an upstream proxy, ProbePing switches
	// from raw TCP dial to HTTP HEAD via that proxy. A bogus proxy URL must
	// surface as a transport-level error (not a silent fallback to direct
	// dial) — otherwise the China-network deployment regresses.
	cfg := &config.Config{
		UpstreamProxy: config.UpstreamProxyConfig{
			URL: "http://127.0.0.1:1", // port 1 is virtually guaranteed closed
		},
	}
	h := newHandlerForTest(cfg)
	rr := postProbePing(t, h, ProbePingRequest{Provider: "anthropic"})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp ProbePingResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.OK {
		t.Errorf("expected ok=false when upstream proxy is unreachable, got ok=true")
	}
	if resp.Error == "" {
		t.Errorf("expected error message when proxied HEAD fails")
	}
}

func TestExtractHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"https://api.anthropic.com", "api.anthropic.com", 443},
		{"https://api.openai.com/v1", "api.openai.com", 443},
		{"http://127.0.0.1:27200", "127.0.0.1", 27200},
		{"http://example.com", "example.com", 80},
		// No scheme at all — treat as https.
		{"api.kimi.com/coding/v1", "api.kimi.com", 443},
		{"api.kimi.com:1443/v1", "api.kimi.com", 1443},
	}
	for _, c := range cases {
		host, port := extractHostPort(c.in)
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("extractHostPort(%q) = (%q, %d), want (%q, %d)",
				c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}
