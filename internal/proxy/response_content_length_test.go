package proxy

// response_content_length_test.go — the response body must not be truncated by a
// Content-Length header describing a body we replaced.
//
// # 🔴 Why this bug survived a suite that already had a real-socket e2e test
//
// `restoreResponseModel` rewrites the response's `model` back to the name the
// client asked for (D-5/N2). That changes the body's LENGTH. The header copied
// from the upstream still advertised the upstream's length, and
// `httputil.ReverseProxy` hands the header map to the client verbatim — so the
// client got `HTTP 200`, a `Content-Length` that was a lie, and a truncated (in
// practice EMPTY) body. Against a real vendor: curl exit 18, "transfer closed
// with 327 bytes remaining".
//
// It could not be caught by the existing httptest e2e, and the reason is worth
// stating because it generalises: **our fake upstreams echo the client's own
// model name back**. That makes the restore a no-op, which changes no lengths,
// which means the stale header happens to be correct. The fake was not merely
// unrealistic — it was unrealistic in precisely the dimension the bug lived in.
//
// So this fence does the one thing the fake was missing: it answers with a
// DIFFERENT model name, the way every real vendor does.
//
// 🔴 It deliberately does NOT need a real vendor. The property is ours, not the
// vendor's, so it belongs in the suite that runs on every commit — the real-
// vendor test (chain_real_upstream_e2e_test.go) found it, this keeps it dead.
//
// 🔴 But it DOES need the request to be mapped, and the routing table is keyed by
// HOST, so an httptest server on 127.0.0.1 maps to nothing. The first version of
// this file skipped that detail and PASSED WITHOUT THE FIX — a green test
// asserting the passthrough path, which is not where the bug lives. The table is
// therefore built at run time around the server's actual host:port
// (provider.OverrideRoutesForTest), and `assertMappingEngaged` fails the test if
// mapping ever silently stops happening, so this cannot quietly go vacuous again.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/providerroutes"
)

// mapHostToZhipuLikeProvider points the routing table at `hostPort` with a
// model_map, so a request to that server takes the MAPPED path — the one the
// truncation bug lives in.
func mapHostToZhipuLikeProvider(t *testing.T, hostPort string) {
	t.Helper()
	yaml := "provider_routes:\n" +
		"  - { host: \"" + hostPort + "\", protocol: anthropic, provider: fencevendor, base_url: \"http://" + hostPort + "\", version: \"/v1\" }\n" +
		"provider_model_maps:\n" +
		"  - provider: fencevendor\n" +
		"    unmatched: passthrough\n" +
		"    models:\n" +
		"      - { match: \"sonnet\", requested_model: \"vendor-own-model-x\" }\n"
	tbl, err := providerroutes.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse test routing table: %v", err)
	}
	t.Cleanup(provider.OverrideRoutesForTest(tbl))
}

// assertMappingEngaged is the anti-vacuity guard. If the request was not mapped,
// `restoreResponseModel` is a no-op, no length changes, and every assertion below
// passes for a reason that has nothing to do with the defect.
func assertMappingEngaged(t *testing.T, deliveredModel, clientModel string) {
	t.Helper()
	if deliveredModel != clientModel {
		t.Fatalf("model restoration did not engage (delivered %q, client asked %q) — this test "+
			"would then be green about the PASSTHROUGH path while the bug lives in the mapped one. "+
			"Fix the test's routing table, do not relax this check.", deliveredModel, clientModel)
	}
}

// upstreamAnsweringWithItsOwnModelName mimics what every real vendor does and
// no fake in this package did: it ignores the requested model name and reports
// its own, which is SHORTER here so a stale Content-Length over-promises.
func upstreamAnsweringWithItsOwnModelName(t *testing.T, ownModel string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `{"id":"msg_own","type":"message","role":"assistant","model":"` + ownModel +
			`","content":[{"type":"text","text":"served"}],"usage":{"input_tokens":7,"output_tokens":3}}`
		w.Header().Set("Content-Type", "application/json")
		// 🔴 An EXPLICIT Content-Length, as a real vendor sends. Without this the
		// Go test server would use chunked encoding and the bug would hide again.
		w.Header().Set("Content-Length", itoaInt64(int64(len(body))))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}))
}

// The headline: what the client reads must be exactly as long as the header says,
// and must be complete JSON.
func TestResponse_BodyIsNotTruncatedWhenTheModelNameIsRestored(t *testing.T) {
	upstream := upstreamAnsweringWithItsOwnModelName(t, "vendor-own-model-x")
	defer upstream.Close()
	mapHostToZhipuLikeProvider(t, strings.TrimPrefix(upstream.URL, "http://"))

	store := &capturingEventStore{}
	p := setupTestProxyWithStore(t, "http://unused.invalid", store)
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-cl", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "mock", RouteSource: "team",
		BaseURL: upstream.URL, PlaintextKey: "k",
		BindingID: "b-cl", CredentialID: "c-cl",
		Priority: 1, FallbackRole: "primary",
	}
	container := *route
	container.Bindings = []*vkeys.ResolvedRoute{route}
	container.BaseURL, container.PlaintextKey = "", ""
	container.ProviderCode, container.ProtocolType = "", ""
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_cl": &container})

	proxySrv := httptest.NewServer(http.HandlerFunc(p.Handle))
	defer proxySrv.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxySrv.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_cl")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	got, readErr := io.ReadAll(resp.Body)

	// 🔴 An unexpected-EOF here IS the bug: the server promised more than it
	// wrote and closed the connection.
	if readErr != nil {
		t.Fatalf("reading the response body failed with %v after %d bytes — the client was told "+
			"Content-Length=%s and the connection closed early. This is the shape a real client "+
			"reports as `transfer closed with N bytes remaining`.",
			readErr, len(got), resp.Header.Get("Content-Length"))
	}
	if len(got) == 0 {
		t.Fatal("the client received a 200 with an EMPTY body")
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" && cl != itoaInt64(int64(len(got))) {
		t.Errorf("Content-Length header says %s but %d bytes were delivered — a header that "+
			"disagrees with the body truncates the response at every well-behaved client", cl, len(got))
	}

	// The payload must be complete and parseable, not merely non-empty.
	var parsed struct {
		Model string `json:"model"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("the delivered body is not complete JSON (%v): %q", err, got)
	}
	if parsed.Usage.OutputTokens == 0 {
		t.Errorf("the delivered body lost its trailing usage block — %q", got)
	}
	assertMappingEngaged(t, parsed.Model, "claude-sonnet-4-5")
}

// The same property on the FALLBACK leg. The switch rebuilds the response from a
// different upstream, so it is a second, independent path to the same mistake.
func TestResponse_BodyIsNotTruncatedAfterAFallbackSwitch(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"overloaded_error","message":"down"}}`)
	}))
	defer down.Close()
	up := upstreamAnsweringWithItsOwnModelName(t, "vendor-own-model-y")
	defer up.Close()
	mapHostToZhipuLikeProvider(t, strings.TrimPrefix(up.URL, "http://"))

	store := &capturingEventStore{}
	p := setupTestProxyWithStore(t, "http://unused.invalid", store)
	mk := func(code, url, id string, prio int64, role string) *vkeys.ResolvedRoute {
		return &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-cl2", Provider: "anthropic", ProtocolType: "anthropic",
			ProviderCode: code, RouteSource: "team", BaseURL: url, PlaintextKey: "k",
			BindingID: id, CredentialID: "c-" + id, Priority: prio, FallbackRole: role,
			RouteGroupID: "rg-cl2", RouteGroupName: "cl2",
		}
	}
	primary := mk("anthropic", down.URL, "b-down", 1, "primary")
	fallback := mk("mock", up.URL, "b-up", 2, "fallback")
	container := *primary
	container.Bindings = []*vkeys.ResolvedRoute{primary, fallback}
	container.BaseURL, container.PlaintextKey = "", ""
	container.ProviderCode, container.ProtocolType = "", ""
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_cl2": &container})

	proxySrv := httptest.NewServer(http.HandlerFunc(p.Handle))
	defer proxySrv.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, proxySrv.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_cl2")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	got, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("reading the body after a switch failed with %v after %d bytes — the fallback "+
			"served, and the client still could not read what it served", readErr, len(got))
	}
	var parsed struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("the body delivered after a switch is not complete JSON (%v): %q", err, got)
	}
	assertMappingEngaged(t, parsed.Model, "claude-sonnet-4-5")
}
