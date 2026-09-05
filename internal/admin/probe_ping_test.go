package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

// rtFunc adapts a function to http.RoundTripper for live-transport spies.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Fence for the 2026-07-29 sysproxy-split fix: when the live forwarding
// transport is wired, ProbePing MUST ride it — for every mode, not only
// engine specs. Here BOTH fallback levels are deliberately poisoned (explicit
// config proxy = dead loopback port, target = unroutable TEST-NET address),
// so the probe can only succeed by consulting the live transport. If someone
// reverts the precedence, this test fails via the dead-proxy path — the exact
// "ping red, forwarding green" false negative from the Win10 VM incident
// (bugfix 2026-07-29-probe-ping-sysproxy-split.md).
func TestProbePing_LiveTransport_PreferredOverConfigAndEnv(t *testing.T) {
	calls := 0
	h := newHandlerForTest(&config.Config{})
	h.cfg.UpstreamProxy.URL = "http://127.0.0.1:1" // dead: fallback path can't succeed
	h.LiveUpstreamTransportFn = func() http.RoundTripper {
		return rtFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			// 404 on purpose: ANY HTTP response proves reachability —
			// same semantics as httpHeadViaProxy.
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     http.Header{},
			}, nil
		})
	}

	// TEST-NET-3 (RFC 5737): unroutable, so a regressed direct/proxied path
	// cannot accidentally green this test.
	rr := postProbePing(t, h, ProbePingRequest{BaseURL: "https://203.0.113.1:9"})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	var resp ProbePingResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body = %q", err, rr.Body.String())
	}
	if !resp.OK {
		t.Errorf("expected ok=true via live transport, got ok=false, error=%q", resp.Error)
	}
	if calls != 1 {
		t.Errorf("live transport RoundTrip calls = %d, want 1 (probe must ride the live route)", calls)
	}
}

// A live-transport dial failure must (a) report ok=false — if the real route
// is dead, ping MUST be red — and (b) never echo raw dial errors, which can
// quote engine spec internals (credentials included). Same hygiene as the
// engine fallback branch.
func TestProbePing_LiveTransportDialFailure_ScrubsError(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	h.LiveUpstreamTransportFn = func() http.RoundTripper {
		return rtFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("dial: proxies fragment user=admin pass=sekret-hunter2")
		})
	}

	rr := postProbePing(t, h, ProbePingRequest{BaseURL: "https://203.0.113.1:9"})

	var resp ProbePingResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.OK {
		t.Fatalf("expected ok=false when the live route fails, got ok=true")
	}
	if resp.Error == "" {
		t.Errorf("expected non-empty scrubbed error when ok=false")
	}
	if strings.Contains(resp.Error, "sekret-hunter2") || strings.Contains(resp.Error, "pass=") {
		t.Errorf("raw dial error leaked into the response: %q", resp.Error)
	}
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

// startTestSocks5 runs a minimal no-auth SOCKS5 CONNECT server (RFC 1928,
// ATYP IPv4/domain) on 127.0.0.1 and returns its address. Just enough protocol
// for the built-in socks5 egress engine to chain through it in tests — not a
// general-purpose implementation.
func startTestSocks5(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks5 listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 262)
				// Greeting: VER NMETHODS METHODS...
				if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
					return
				}
				if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0}); err != nil { // no-auth
					return
				}
				// Request: VER CMD RSV ATYP
				if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 1 {
					return
				}
				var host string
				switch buf[3] {
				case 1: // IPv4
					if _, err := io.ReadFull(c, buf[:4]); err != nil {
						return
					}
					host = net.IP(buf[:4]).String()
				case 3: // domain
					if _, err := io.ReadFull(c, buf[:1]); err != nil {
						return
					}
					n := int(buf[0])
					if _, err := io.ReadFull(c, buf[:n]); err != nil {
						return
					}
					host = string(buf[:n])
				default:
					return
				}
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				port := int(buf[0])<<8 | int(buf[1])
				up, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 3*time.Second)
				if err != nil {
					_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// Engine-spec upstreams (socks5 chain / mihomo fragment) must ping through the
// egress engine registry — NOT url.Parse — and must never echo the spec (which
// carries proxy credentials) back to the caller. Fences the 2026-07-19 bug
// where a mihomo fragment in upstream_proxy.url failed EVERY ping with
// "invalid proxy URL: parse proxies:\n..." (spec + credentials leaked into the
// response, and the vault connectivity test reported a false
// PROXY_UPSTREAM_UNREACHABLE for every credential).
func TestProbePing_EngineSpecFragment_NoSecretLeak(t *testing.T) {
	fragment := "proxies:\n" +
		"  - name: \"test-exit\"\n" +
		"    type: socks5\n" +
		"    server: 127.0.0.1\n" +
		"    port: 1\n" +
		"    username: user1\n" +
		"    password: SECRETXYZ\n"
	cfg := &config.Config{UpstreamProxy: config.UpstreamProxyConfig{URL: fragment}}
	h := newHandlerForTest(cfg)

	// Live local target so a build WITH the mihomo engine still gets a
	// deterministic dial failure (port 1 exit) rather than touching the net.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rr := postProbePing(t, h, ProbePingRequest{BaseURL: srv.URL})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "SECRETXYZ") || strings.Contains(body, "user1") {
		t.Errorf("response leaked egress spec credentials: %q", body)
	}
	if strings.Contains(body, "invalid proxy URL") {
		t.Errorf("fragment fed to url.Parse (mode-2 path) instead of the egress engine: %q", body)
	}
	var resp ProbePingResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body = %q", err, body)
	}
	if !resp.OK && resp.Error == "" {
		t.Errorf("expected a (sanitized) error message when ok=false")
	}
}

func TestProbePing_EngineSpecChain_ReachesTargetThroughEngine(t *testing.T) {
	hop1 := startTestSocks5(t)
	hop2 := startTestSocks5(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound) // any HTTP response counts as reachable
	}))
	defer srv.Close()

	chain := "socks5://" + hop1 + ",socks5://" + hop2
	cfg := &config.Config{UpstreamProxy: config.UpstreamProxyConfig{URL: chain}}
	h := newHandlerForTest(cfg)

	rr := postProbePing(t, h, ProbePingRequest{BaseURL: srv.URL})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	var resp ProbePingResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body = %q", err, rr.Body.String())
	}
	if !resp.OK {
		t.Errorf("expected ok=true through the socks5 chain, got error=%q", resp.Error)
	}
}

// countingRoundTripper fakes the live forwarding transport: serves a fixed
// response and counts uses, so the test can prove the engine branch rode it
// instead of building a throwaway engine dialer.
type countingRoundTripper struct{ calls int }

func (c *countingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls++
	return &http.Response{
		StatusCode: http.StatusNotFound, // any HTTP response counts as reachable
		Body:       http.NoBody,
		Request:    req,
		Header:     http.Header{},
	}, nil
}

func TestProbePing_EngineSpec_PrefersLiveTransport(t *testing.T) {
	fragment := "proxies:\n  - name: x\n    type: socks5\n    server: 127.0.0.1\n    port: 1\n"
	cfg := &config.Config{UpstreamProxy: config.UpstreamProxyConfig{URL: fragment}}
	h := newHandlerForTest(cfg)
	rt := &countingRoundTripper{}
	h.LiveUpstreamTransportFn = func() http.RoundTripper { return rt }

	rr := postProbePing(t, h, ProbePingRequest{BaseURL: "http://upstream.example:9"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	var resp ProbePingResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body = %q", err, rr.Body.String())
	}
	if !resp.OK {
		t.Errorf("expected ok=true via the live transport, got error=%q", resp.Error)
	}
	if rt.calls != 1 {
		t.Errorf("live transport used %d times, want 1 (engine branch must ride it, not rebuild)", rt.calls)
	}
}

func TestProbePing_EngineSpecChain_DeadHopFailsSanitized(t *testing.T) {
	// First hop is a closed port → the engine dial fails. The response must
	// carry a classified/sanitized error, not a raw url.Parse complaint.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	ln.Close()

	chain := "socks5://" + deadAddr + ",socks5://" + deadAddr
	cfg := &config.Config{UpstreamProxy: config.UpstreamProxyConfig{URL: chain}}
	h := newHandlerForTest(cfg)

	rr := postProbePing(t, h, ProbePingRequest{Provider: "anthropic"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp ProbePingResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.OK {
		t.Errorf("expected ok=false through a dead chain, got ok=true")
	}
	if resp.Error == "" {
		t.Errorf("expected non-empty error when ok=false")
	}
	if strings.Contains(resp.Error, "invalid proxy URL") {
		t.Errorf("chain fed to url.Parse instead of the egress engine: %q", resp.Error)
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

// ── source_ref: the probe must test the CREDENTIAL's upstream ───────────────
//
// 2026-08-03. Before this, ProbePing resolved its target from `provider` alone:
// a personal entry carrying its own base_url (self-hosted gateway, OAuth
// ingress) was probed against the provider's PUBLIC host, which it never talks
// to. The verdict then tracked the wrong host in both directions — red while
// the real gateway was healthy, and GREEN while it was down. A green row for an
// upstream that is unreachable is the more dangerous half.

// The resolver's answer must WIN over a caller-supplied base_url. If the
// caller's value could override it, the CLI would remain a second source of
// truth for an address only the proxy can see — the split this field closes.
func TestProbePing_SourceRefResolutionBeatsCallerSuppliedBaseURL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			c.Close()
		}
	}()
	real := "http://" + ln.Addr().String()

	h := newHandlerForTest(&config.Config{})
	var askedFor string
	h.ResolveUpstreamFn = func(sourceRef, protocolHint string) (string, error) {
		askedFor = sourceRef
		return real, nil
	}

	// The caller names a DEAD address; only the resolver knows the live one.
	body, _ := json.Marshal(ProbePingRequest{
		Provider:  "anthropic",
		BaseURL:   "http://127.0.0.1:1/dead",
		SourceRef: "my-gateway-key",
	})
	rr := httptest.NewRecorder()
	h.ProbePing(rr, httptest.NewRequest(http.MethodPost, "/admin/probe/ping", bytes.NewReader(body)))

	var resp ProbePingResponse
	if derr := json.NewDecoder(rr.Body).Decode(&resp); derr != nil {
		t.Fatalf("decode: %v", derr)
	}
	if askedFor != "my-gateway-key" {
		t.Errorf("resolver was not consulted for the credential (asked for %q)", askedFor)
	}
	if !resp.OK {
		t.Errorf("probe used the caller's dead base_url instead of the resolved upstream: %+v", resp)
	}
	if resp.ResolvedUpstream != real {
		t.Errorf("resolved_upstream not echoed back (%q != %q) — the caller cannot then DISPLAY "+
			"the address that was tested, which is what 展示=执行 requires", resp.ResolvedUpstream, real)
	}
}

// 🔴 An unresolvable reference must FAIL, never silently degrade to the
// provider default. That degradation is the original defect: it produced a
// verdict uncorrelated with the credential under test.
func TestProbePing_UnresolvableSourceRefRefusesInsteadOfGuessing(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(string, string) (string, error)
	}{
		{"error", func(string, string) (string, error) { return "", errors.New("not in vault") }},
		{"empty", func(string, string) (string, error) { return "", nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandlerForTest(&config.Config{})
			h.ResolveUpstreamFn = tc.fn

			body, _ := json.Marshal(ProbePingRequest{Provider: "anthropic", SourceRef: "ghost"})
			rr := httptest.NewRecorder()
			h.ProbePing(rr, httptest.NewRequest(http.MethodPost, "/admin/probe/ping", bytes.NewReader(body)))

			var resp ProbePingResponse
			if derr := json.NewDecoder(rr.Body).Decode(&resp); derr != nil {
				t.Fatalf("decode: %v", derr)
			}
			if resp.OK {
				t.Fatal("probe reported OK for a credential whose upstream could not be resolved")
			}
			// Must not have fallen back to the public provider host.
			if strings.Contains(resp.Host, "anthropic.com") || strings.Contains(resp.ResolvedUpstream, "anthropic.com") {
				t.Errorf("fell back to the provider's public host (host=%q resolved=%q). A green/red "+
					"verdict about api.anthropic.com says nothing about this credential's gateway",
					resp.Host, resp.ResolvedUpstream)
			}
			if resp.Error == "" {
				t.Error("refusal carried no explanation; 失败要显眼 requires an actionable reason")
			}
			// Wire contract (2026-09-05): the refusal must carry a stable code.
			// The CLI keys PROBE_UPSTREAM_UNRESOLVED off this field so users
			// are told "the proxy could not resolve this key" rather than
			// "upstream unreachable — check your network".
			if resp.ErrorCode != ProbePingErrCodeUpstreamUnresolved {
				t.Errorf("error_code = %q, want %q", resp.ErrorCode, ProbePingErrCodeUpstreamUnresolved)
			}
		})
	}
}

// Backward compatibility: an older CLI sends no source_ref and must keep its
// exact previous behavior (the field is additive, not a migration).
func TestProbePing_WithoutSourceRefBehaviourIsUnchanged(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			c.Close()
		}
	}()

	h := newHandlerForTest(&config.Config{})
	h.ResolveUpstreamFn = func(string, string) (string, error) {
		t.Error("resolver consulted although the caller sent no source_ref")
		return "", errors.New("must not be called")
	}
	body, _ := json.Marshal(ProbePingRequest{Provider: "anthropic", BaseURL: "http://" + ln.Addr().String()})
	rr := httptest.NewRecorder()
	h.ProbePing(rr, httptest.NewRequest(http.MethodPost, "/admin/probe/ping", bytes.NewReader(body)))

	var resp ProbePingResponse
	if derr := json.NewDecoder(rr.Body).Decode(&resp); derr != nil {
		t.Fatalf("decode: %v", derr)
	}
	if !resp.OK {
		t.Errorf("legacy caller path regressed: %+v", resp)
	}
	if resp.ResolvedUpstream != "" {
		t.Errorf("resolved_upstream must stay empty when the caller supplied the target, got %q", resp.ResolvedUpstream)
	}
}
