package proxy

// chain_live_e2e_test.go — the fallback flow end to end over REAL sockets
// (openspec change `aliyun-aigw-p0-upstream-fallback`, task 6.3f / the L2-wire
// row of 6.1's assertion table).
//
// # 🔴 How this differs from every other test in the package
//
// The rest of the chain tests swap the proxy's transport for a capture stub.
// That is the right tool for asserting ordering and attribution, but it means
// no byte ever crosses a socket, so it cannot see anything that lives in the
// transport itself: TLS setup, connection reuse, header canonicalisation, a
// hop-by-hop header being stripped, the client's own view of the response.
//
// This one runs the real thing:
//
//	real curl  →  real proxy listener  →  real upstream listeners
//
// The primary upstream is a real HTTP server that answers 503. The fallback is
// a real HTTP server that answers 200. Nothing is stubbed, and the client is an
// external process, so what it prints is what a user would see.
//
// 🚫 It is NOT a substitute for task 6.6 (three environments) or 6.1's L3/L4
// rows: everything here is localhost and the event store is in-process, so
// ODS→DWD propagation and cross-dashboard agreement remain unproven.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func TestChain_LiveEndToEndOverRealSockets(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}

	var primaryHits, fallbackHits atomic.Int32

	// ── The primary upstream: a real server that is down ───────────────────
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"overloaded_error","message":"upstream is down"}}`))
	}))
	defer primary.Close()

	// ── The fallback upstream: a real server that answers ──────────────────
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits.Add(1)
		// 🔴 Echo the model the client asked for. The client-facing model name
		// must be unchanged by a switch (I6), and only a real round trip can
		// show what the client actually received.
		var body struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_live_1","type":"message","role":"assistant","model":"` +
			body.Model + `","content":[{"type":"text","text":"served by the fallback"}],` +
			`"usage":{"input_tokens":11,"output_tokens":22}}`))
	}))
	defer fallback.Close()

	// ── The chain, pointing at those real addresses ────────────────────────
	store := &capturingEventStore{}
	p := setupTestProxyWithStore(t, "http://unused.invalid", store)
	mk := func(code, url, bindingID string, prio int64, role string) *vkeys.ResolvedRoute {
		return &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-live", Provider: "anthropic", ProtocolType: "anthropic",
			ProviderCode: code, RouteSource: "team",
			BaseURL: url, PlaintextKey: "key-" + bindingID,
			BindingID: bindingID, CredentialID: "cred-" + bindingID,
			Priority: prio, FallbackRole: role,
			RouteGroupID: "rg-live", RouteGroupName: "live-chain",
		}
	}
	p1 := mk("anthropic", primary.URL, "b-primary", 1, "primary")
	f1 := mk("mock", fallback.URL, "b-fallback", 2, "fallback")
	container := *p1
	container.Bindings = []*vkeys.ResolvedRoute{p1, f1}
	container.BaseURL, container.PlaintextKey = "", ""
	container.ProviderCode, container.ProtocolType = "", ""
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_live": &container})

	// ── The proxy, on a real port ──────────────────────────────────────────
	proxySrv := httptest.NewServer(http.HandlerFunc(p.Handle))
	defer proxySrv.Close()

	t.Logf("primary  upstream (503) : %s", primary.URL)
	t.Logf("fallback upstream (200) : %s", fallback.URL)
	t.Logf("proxy                   : %s", proxySrv.URL)

	// ── A real external client ─────────────────────────────────────────────
	out, err := exec.Command("curl", "-sS", "-D", "-", "-o", "/tmp/aikey_live_body.json",
		"-H", "Content-Type: application/json",
		"-H", "Authorization: Bearer aikey_team_live",
		"-d", `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`,
		proxySrv.URL+"/v1/messages").CombinedOutput()
	if err != nil {
		t.Fatalf("curl failed: %v\n%s", err, out)
	}
	headers := string(out)
	t.Logf("---- response headers the CLIENT received ----\n%s", strings.TrimSpace(headers))

	// ── What the client got ────────────────────────────────────────────────
	if !strings.Contains(headers, "200 OK") {
		t.Fatalf("client did not receive 200:\n%s", headers)
	}
	// 🔴 The switch is announced. Provider code only — never the resolved
	// base_url, which may be a customer's internal gateway (contract §3).
	if !strings.Contains(headers, "X-Aikey-Fallback:") {
		t.Error("no X-Aikey-Fallback header — the client was switched to another vendor " +
			"and has no way to know which one served it")
	}
	if strings.Contains(headers, primary.URL) || strings.Contains(headers, fallback.URL) {
		t.Error("a raw upstream address leaked into the response headers — an upstream " +
			"address may be a customer's internal gateway, and echoing it to every key " +
			"holder broadcasts internal topology")
	}

	// ── Both upstreams were really called, in order ────────────────────────
	if primaryHits.Load() != 1 {
		t.Errorf("primary upstream received %d requests, want 1", primaryHits.Load())
	}
	if fallbackHits.Load() != 1 {
		t.Errorf("fallback upstream received %d requests, want 1", fallbackHits.Load())
	}

	// ── The ledger, from a request that crossed real sockets ───────────────
	evs := store.recorded()
	printLedger(t, evs)
	if len(evs) != 2 {
		t.Fatalf("ledger has %d rows, want 2", len(evs))
	}
	charged := 0
	for _, ev := range evs {
		if ev.InputTokens > 0 || ev.OutputTokens > 0 {
			charged++
			if ev.ServedProvider != "mock" {
				t.Errorf("charge attributed to %q, want mock (the hop that served)", ev.ServedProvider)
			}
		}
	}
	if charged != 1 {
		t.Errorf("%d rows carry tokens, want exactly 1", charged)
	}
	if evs[0].TraceID != evs[1].TraceID {
		t.Error("the two hops of one client request do not share a trace_id")
	}
}
