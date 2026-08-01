package proxy

// chain_real_upstream_e2e_test.go — the fallback flow against REAL VENDORS.
//
// # 🔴 What this covers that chain_live_e2e_test.go cannot
//
// That test already runs real sockets, a real proxy listener and a real external
// client — but both upstreams are `httptest` servers we wrote. So every property
// that depends on the vendor rather than on us is untested there:
//
//   - a real TLS handshake to a real host, with a real certificate chain
//   - the vendor's OWN error body, in the vendor's own shape and language.
//     Anthropic answers `{"type":"error","error":{"type":"authentication_error",
//     …},"request_id":…}`; Zhipu answers `{"error":{"message":"令牌已过期或验证
//     不正确","type":"401"}}`. Nothing we would have thought to write by hand
//     produces those two shapes, and a switch decision that reads the body is
//     only as good as the bodies it has actually met.
//   - a real success body with real token counts, so the ledger is charged from
//     a vendor's numbers rather than from a literal we chose
//   - the vendor's own view of the model name
//
// # The chain
//
//	hop 1  api.anthropic.com          + a deliberately invalid key  → real 401
//	hop 2  open.bigmodel.cn/api/anthropic + the real GLM key        → real 200
//
// 🔴 Cross-VENDOR on purpose. A two-hop chain inside one vendor shares that
// vendor's error shapes, auth scheme and model vocabulary, so it cannot show
// whether the switch survives crossing any of them — and "switch to a different
// vendor when this one is down" is the entire product claim.
//
// 🔴 The failure is induced with a BAD CREDENTIAL, not a bad address. An
// unroutable host fails in the dialer and never reaches the vendor; this reaches
// Anthropic, is understood by Anthropic, and is refused by Anthropic. Neither of
// those 401 bodies contains "revoked", so `isHardRevoked` stays false and the
// run has no quarantine side-effect on the pool.
//
// # 🚫 What it still does not prove
//
// The event store is in-process, so this is the L2-wire row of 6.1 and NOT L3
// (ODS→DWD) or L4 (dashboards). It is one node, so per-node cooldown is out of
// scope. And it is one request — cooldown, switch-back and streaming have their
// own tests.
//
// # Gating
//
// Requires AIKEY_E2E_REAL_UPSTREAM=1 plus CLAUDE-side and GLM keys, because it
// spends real quota and needs the network. 🔴 A skip is NOT a pass: a run
// without these has not covered a real vendor, and 6.1 must not be ticked from
// a run that skipped this file.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

const (
	realAnthropicBase = "https://api.anthropic.com"
	realZhipuBase     = "https://open.bigmodel.cn/api/anthropic"
)

func requireRealUpstream(t *testing.T) string {
	t.Helper()
	if os.Getenv("AIKEY_E2E_REAL_UPSTREAM") != "1" {
		t.Skip("AIKEY_E2E_REAL_UPSTREAM != 1 — REAL VENDORS NOT COVERED by this run")
	}
	glm := os.Getenv("GLM_API_KEY")
	if glm == "" {
		t.Skip("GLM_API_KEY unset — REAL VENDORS NOT COVERED by this run")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	return glm
}

// realChainProxy wires a two-hop chain whose hops are real vendor endpoints.
func realChainProxy(t *testing.T, glmKey string, store *capturingEventStore) *Proxy {
	t.Helper()
	p := setupTestProxyWithStore(t, "http://unused.invalid", store)
	mk := func(code, url, key, bindingID string, prio int64, role string) *vkeys.ResolvedRoute {
		return &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-real", Provider: "anthropic", ProtocolType: "anthropic",
			ProviderCode: code, RouteSource: "team",
			BaseURL: url, PlaintextKey: key,
			BindingID: bindingID, CredentialID: "cred-" + bindingID,
			Priority: prio, FallbackRole: role,
			RouteGroupID: "rg-real", RouteGroupName: "real-vendor-chain",
		}
	}
	// 🔴 An invalid but WELL-FORMED key. A malformed one risks being rejected by
	// something other than authentication, which would make the hop fail for a
	// reason the test did not choose.
	primary := mk("anthropic", realAnthropicBase, "sk-ant-api03-deliberately-invalid-for-failover-test",
		"b-real-primary", 1, "primary")
	fallback := mk("zhipu", realZhipuBase, glmKey, "b-real-fallback", 2, "fallback")

	container := *primary
	container.Bindings = []*vkeys.ResolvedRoute{primary, fallback}
	container.BaseURL, container.PlaintextKey = "", ""
	container.ProviderCode, container.ProtocolType = "", ""
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_real": &container})
	return p
}

// 🔴 The headline: a real vendor refuses, a DIFFERENT real vendor serves, and
// the client — an external process — gets a real answer.
func TestChain_RealVendorFailover(t *testing.T) {
	glmKey := requireRealUpstream(t)

	store := &capturingEventStore{}
	p := realChainProxy(t, glmKey, store)
	proxySrv := newLocalServer(p)
	defer proxySrv.Close()

	t.Logf("hop 1 (expect real 401): %s", realAnthropicBase)
	t.Logf("hop 2 (expect real 200): %s", realZhipuBase)

	bodyPath := t.TempDir() + "/body.json"
	// #nosec G204 -- every argument is a test-local constant or a key read from
	// the environment by the operator running this suite.
	out, err := exec.Command("curl", "-sS", "-D", "-", "-o", bodyPath,
		"-H", "Content-Type: application/json",
		"-H", "Authorization: Bearer aikey_team_real",
		"-d", `{"model":"claude-sonnet-4-5","max_tokens":32,"messages":[{"role":"user","content":"reply with the single word OK"}]}`,
		proxySrv.URL+"/v1/messages").CombinedOutput()
	if err != nil {
		t.Fatalf("curl failed: %v\n%s", err, out)
	}
	headers := string(out)
	t.Logf("---- headers the CLIENT received ----\n%s", strings.TrimSpace(headers))

	if !strings.Contains(headers, "200 OK") {
		raw, _ := os.ReadFile(bodyPath)
		t.Fatalf("client did not receive 200 — a real vendor refused and the chain did not "+
			"recover:\nheaders:\n%s\nbody:\n%s", headers, raw)
	}

	// 🔴 The switch is announced, by provider code only. A raw base_url may be a
	// customer's internal gateway; echoing it to every key holder broadcasts
	// internal topology (contract §3).
	if !strings.Contains(headers, "X-Aikey-Fallback:") {
		t.Error("no X-Aikey-Fallback header — the client was served by a different vendor than " +
			"the one it was configured against and has no way to know which")
	}
	for _, leak := range []string{realAnthropicBase, realZhipuBase, "open.bigmodel.cn", "api.anthropic.com"} {
		if strings.Contains(headers, leak) {
			t.Errorf("a raw upstream address (%q) leaked into the response headers", leak)
		}
	}
	// The invalid key must never appear anywhere the client can see.
	if strings.Contains(headers, "sk-ant-api03") || strings.Contains(headers, glmKey) {
		t.Error("🔴 a credential leaked into the response headers")
	}

	// ── The body really came from Zhipu ────────────────────────────────────
	raw, readErr := os.ReadFile(bodyPath)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}
	var served struct {
		Type    string `json:"type"`
		Model   string `json:"model"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &served); err != nil {
		t.Fatalf("served body is not JSON: %v\n%s", err, raw)
	}
	t.Logf("served model=%q tokens in/out=%d/%d content=%q",
		served.Model, served.Usage.InputTokens, served.Usage.OutputTokens,
		firstText(served.Content))
	if served.Usage.InputTokens <= 0 || served.Usage.OutputTokens <= 0 {
		t.Errorf("served body carries no real token usage (in=%d out=%d) — the ledger below is "+
			"then charged from nothing", served.Usage.InputTokens, served.Usage.OutputTokens)
	}

	// ── The ledger, from a request that crossed two real vendors ───────────
	evs := store.recorded()
	printLedger(t, evs)
	if len(evs) != 2 {
		t.Fatalf("ledger has %d rows, want 2 (one refused hop, one served hop)", len(evs))
	}
	if evs[0].TraceID != evs[1].TraceID {
		t.Error("the two hops of one client request do not share a trace_id — the switch is then " +
			"unreconstructable from the ledger")
	}
	charged := 0
	for _, ev := range evs {
		if ev.InputTokens > 0 || ev.OutputTokens > 0 {
			charged++
			if ev.ServedProvider != "zhipu" {
				t.Errorf("charge attributed to %q, want zhipu — the hop that actually served",
					ev.ServedProvider)
			}
		}
	}
	if charged != 1 {
		t.Errorf("%d ledger rows carry tokens, want exactly 1 — 🔴 the refused hop must not be "+
			"billed, and the served hop must be", charged)
	}
}

// 🔴 I6, asked of a REAL vendor: the model name the client sees must not change
// because we switched behind its back.
//
// This is the assertion an httptest fallback can never make honestly, because
// there we choose what the fake echoes. Zhipu's anthropic endpoint accepts
// `claude-sonnet-4-5` and answers with its OWN name (`glm-4.x`) — so whether the
// client's contract holds is decided by the proxy, against a body we did not
// write.
//
// Reported rather than assumed: if this fails, the switch is visible to every
// client that reads `model` off the response, which is most SDK retry logic.
func TestChain_RealVendorFailover_ClientFacingModelName(t *testing.T) {
	glmKey := requireRealUpstream(t)

	store := &capturingEventStore{}
	p := realChainProxy(t, glmKey, store)
	proxySrv := newLocalServer(p)
	defer proxySrv.Close()

	bodyPath := t.TempDir() + "/body.json"
	// #nosec G204 -- test-local constants plus an operator-supplied key.
	if out, err := exec.Command("curl", "-sS", "-o", bodyPath,
		"-H", "Content-Type: application/json",
		"-H", "Authorization: Bearer aikey_team_real",
		"-d", `{"model":"claude-sonnet-4-5","max_tokens":32,"messages":[{"role":"user","content":"reply with the single word OK"}]}`,
		proxySrv.URL+"/v1/messages").CombinedOutput(); err != nil {
		t.Fatalf("curl failed: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var served struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(raw, &served); err != nil {
		t.Fatalf("served body is not JSON: %v\n%s", err, raw)
	}

	const asked = "claude-sonnet-4-5"
	if served.Model != asked {
		t.Errorf("🔴 I6: the client asked for %q and the response says %q. The switch is therefore "+
			"VISIBLE to any client that reads the model off the response — which is most SDK retry "+
			"and telemetry code. Either the response model is normalised back to the client口径, or "+
			"this is a documented limitation of switching across vendors; it must not be neither.",
			asked, served.Model)
	}
}

func firstText(c []struct {
	Text string `json:"text"`
}) string {
	if len(c) == 0 {
		return ""
	}
	return c[0].Text
}

// newLocalServer puts the proxy on a real loopback port.
func newLocalServer(p *Proxy) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(p.Handle))
}
