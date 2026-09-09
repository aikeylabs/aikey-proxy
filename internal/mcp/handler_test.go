package mcp

// handler_test.go — P1 acceptance and the five P1 fences.
//
// 🔴 Every test here drives the REAL handler through a real http.ServeMux via
// RegisterRoutes. Nothing re-implements a simplified router: the project rule
// is that tests exercise the code the user actually reaches, because a test
// against a stand-in proves the stand-in works.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/fallbackpolicy"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const (
	testToken   = "aikey_app_testtoken"
	testOrg     = "org_42"
	testSeat    = "seat_7"
	testToolset = "devtools"
)

// stubResolver is a two-line TokenResolver. It exists so these tests can drive
// the real handler without standing up a vault — the seam auth.go declares for
// exactly this reason.
type stubResolver map[string]*vkeys.ResolvedRoute

func (s stubResolver) Resolve(token string) *vkeys.ResolvedRoute { return s[token] }

func newTestServer(t *testing.T, tools []mcpwire.Tool) (*http.ServeMux, *Handler) {
	t.Helper()
	h := NewHandler(Config{
		Catalog: &StaticCatalog{Toolsets: map[string]ToolsetView{
			testToolset: {Slug: testToolset, Title: "Dev Tools", Tools: tools},
		}},
		Resolver: stubResolver{
			testToken: {OrgID: testOrg, SeatID: testSeat},
		},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, h
}

func fixtureTools() []mcpwire.Tool {
	return []mcpwire.Tool{
		{
			Name:        "query_readonly",
			Description: "Run a read-only SQL query.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"]}`),
		},
		{
			Name:        "create_issue",
			Description: "Open a GitHub issue.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"title":{"type":"string"}}}`),
		},
	}
}

// rpc posts a JSON-RPC message and returns the recorder plus the decoded
// envelope (which is the zero value for empty bodies, e.g. 202/204).
func rpc(t *testing.T, mux *http.ServeMux, path, token, body string, hdr map[string]string) (*httptest.ResponseRecorder, mcpwire.Envelope) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var env mcpwire.Envelope
	if raw := rec.Body.Bytes(); len(strings.TrimSpace(string(raw))) > 0 {
		_ = json.Unmarshal(raw, &env)
	}
	return rec, env
}

func initializeBody(version string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + version +
		`","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}`
}

func aikeyCode(t *testing.T, env mcpwire.Envelope) string {
	t.Helper()
	if env.Error == nil {
		t.Fatalf("expected an error envelope, got result=%s", env.Result)
	}
	var d errorData
	if err := json.Unmarshal(env.Error.Data, &d); err != nil {
		t.Fatalf("error data is not the documented shape (%s): %v", env.Error.Data, err)
	}
	return d.AiKeyCode
}

// ---------------------------------------------------------------------------
// P1 acceptance: handshake → tools/list
// ---------------------------------------------------------------------------

// TestHandshakeThenToolsList is the P1 exit condition in test form: a client
// connects, negotiates, and receives the toolset's tools.
func TestHandshakeThenToolsList(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())

	rec, env := rpc(t, mux, "/mcp/"+testToolset, testToken, initializeBody("2025-06-18"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize returned %d: %s", rec.Code, rec.Body)
	}
	sessionID := rec.Header().Get(mcpwire.HeaderSessionID)
	if sessionID == "" {
		t.Fatal("initialize did not mint an Mcp-Session-Id")
	}
	if got := rec.Header().Get(mcpwire.HeaderProtocolVersion); got != "2025-06-18" {
		t.Errorf("MCP-Protocol-Version header = %q, want the negotiated revision", got)
	}

	var res mcpwire.InitializeResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatalf("initialize result: %v", err)
	}
	if res.ProtocolVersion != "2025-06-18" {
		t.Errorf("negotiated %q, client asked for 2025-06-18", res.ProtocolVersion)
	}
	// 🔴 listChanged must stay false: the gateway freezes on drift instead of
	// pushing, so advertising it promises a notification that never arrives.
	if res.Capabilities.Tools == nil || res.Capabilities.Tools.ListChanged {
		t.Errorf("tools.listChanged should be advertised false, got %+v", res.Capabilities.Tools)
	}

	_, listEnv := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		map[string]string{mcpwire.HeaderSessionID: sessionID})
	var list mcpwire.ListToolsResult
	if err := json.Unmarshal(listEnv.Result, &list); err != nil {
		t.Fatalf("tools/list result: %v (err=%+v)", err, listEnv.Error)
	}
	if len(list.Tools) != 2 {
		t.Fatalf("tools/list returned %d tools, want 2", len(list.Tools))
	}
	if list.Tools[0].Name != "query_readonly" || list.Tools[1].Name != "create_issue" {
		t.Errorf("tools/list returned %q, %q", list.Tools[0].Name, list.Tools[1].Name)
	}
}

// TestEmptyToolsetSerialisesAsArrayNotNull — `"tools": null` makes several
// clients throw; `[]` is unambiguously "this toolset is empty".
func TestEmptyToolsetSerialisesAsArrayNotNull(t *testing.T) {
	mux, _ := newTestServer(t, nil)
	rec, _ := rpc(t, mux, "/mcp/"+testToolset, testToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	if !strings.Contains(rec.Body.String(), `"tools":[]`) {
		t.Errorf("empty toolset must serialise tools as [], got %s", rec.Body)
	}
}

// TestNotificationGetsNoBody — answering a notification is a protocol
// violation several clients treat as fatal.
func TestNotificationGetsNoBody(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	rec, _ := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)
	if rec.Code != http.StatusAccepted {
		t.Errorf("notification returned %d, want 202", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "" {
		t.Errorf("notification must get an empty body, got %q", rec.Body.String())
	}
}

// TestSlugLookupIsCaseInsensitive — one definition of slug equality, or the
// symptom is a 404 that reads like a permissions problem.
func TestSlugLookupIsCaseInsensitive(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	rec, _ := rpc(t, mux, "/mcp/DevTools", testToken, initializeBody("2025-06-18"), nil)
	if rec.Code != http.StatusOK {
		t.Errorf("/mcp/DevTools returned %d; slug comparison must be normalised", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Fence 1.F4 — no bearer / wrong bearer → 401 with a spec-shaped challenge
// ---------------------------------------------------------------------------

// TestFence_1F4_UnauthenticatedGets401WithResourceMetadata.
//
// The resource_metadata parameter is what makes the 401 USEFUL: an RFC 9728
// client follows it, reads that no authorization server is offered, and prompts
// the user for a token — instead of hanging in a discovery loop.
func TestFence_1F4_UnauthenticatedGets401WithResourceMetadata(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())

	for _, tc := range []struct{ name, token string }{
		{"no bearer", ""},
		{"unknown bearer", "aikey_app_not_a_real_token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, _ := rpc(t, mux, "/mcp/"+testToolset, tc.token, initializeBody("2025-06-18"), nil)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", rec.Code)
			}
			challenge := rec.Header().Get("WWW-Authenticate")
			if challenge == "" {
				t.Fatal("401 carried no WWW-Authenticate header")
			}
			if !strings.HasPrefix(challenge, "Bearer ") {
				t.Errorf("challenge must use the Bearer scheme, got %q", challenge)
			}
			if !strings.Contains(challenge, `resource_metadata="http://127.0.0.1:8787/.well-known/oauth-protected-resource"`) {
				t.Errorf("challenge must point at the RFC 9728 document, got %q", challenge)
			}
		})
	}
}

// TestUnauthenticatedRepliesAreIndistinguishable — telling a prober that a
// token "used to exist" is an enumeration oracle for free.
func TestUnauthenticatedRepliesAreIndistinguishable(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	a, _ := rpc(t, mux, "/mcp/"+testToolset, "", initializeBody("2025-06-18"), nil)
	b, _ := rpc(t, mux, "/mcp/"+testToolset, "aikey_app_wrong", initializeBody("2025-06-18"), nil)
	if a.Body.String() != b.Body.String() {
		t.Errorf("missing-token and wrong-token replies differ:\n  %s\n  %s", a.Body, b.Body)
	}
}

// TestProtectedResourceMetadataAlwaysEmitsAuthorizationServers is task 1.8a.
//
// 🔴 An EMPTY ARRAY says "bearer accepted, no authorization server offered" and
// makes a compliant client prompt for a token. An ABSENT field says "no
// statement made" and makes the same client go discover, then hang. The two
// differ by one `omitempty` struct tag, which is why this is asserted on the
// serialised bytes rather than on the Go value.
func TestProtectedResourceMetadataAlwaysEmitsAuthorizationServers(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("metadata returned %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"authorization_servers":[]`) {
		t.Fatalf("authorization_servers must be an EXPLICIT empty array, got: %s", body)
	}
	var doc ProtectedResourceMetadata
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Resource != "http://127.0.0.1:8787/mcp" {
		t.Errorf("resource = %q", doc.Resource)
	}
	if len(doc.BearerMethodsSupported) == 0 {
		t.Error("bearer_methods_supported must tell the client where to put the token")
	}
}

// ---------------------------------------------------------------------------
// Fence 1.F5 — unsupported protocol revision
// ---------------------------------------------------------------------------

// TestFence_1F5_UnsupportedProtocolIsAnsweredWithOurs.
//
// 🔴 CORRECTED 2026-09-01. This fence originally asserted a refusal, matching
// R1 as first written. Measuring against the real client showed that refusing
// makes the gateway unusable by every current MCP client, and the spec is a MUST
// in the other direction:
//
//	"Otherwise, the server MUST respond with another protocol version it
//	 supports… If the client does not support the version in the server's
//	 response, it SHOULD disconnect."
//
// What R1 actually protects against — a SILENT downgrade — still holds, and this
// test pins the part that makes it non-silent: the response CARRIES the version,
// so the client can compare and disconnect.
func TestFence_1F5_UnsupportedProtocolIsAnsweredWithOurs(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	rec, env := rpc(t, mux, "/mcp/"+testToolset, testToken, initializeBody("2099-01-01"), nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("handshake returned %d; the spec requires answering with a supported revision", rec.Code)
	}
	if env.Error != nil {
		t.Fatalf("handshake was refused (%+v); the spec requires answering with a supported revision", env.Error)
	}
	var res mcpwire.InitializeResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatal(err)
	}
	// 🔴 The answer must be OUR newest, and it must be PRESENT — a response that
	// omitted the version would be the silent downgrade R1 forbids, because the
	// client would have nothing to compare against.
	if res.ProtocolVersion != mcpwire.SupportedProtocolVersions[0] {
		t.Errorf("answered %q, want our newest %q", res.ProtocolVersion, mcpwire.SupportedProtocolVersions[0])
	}
	if got := rec.Header().Get(mcpwire.HeaderProtocolVersion); got != string(mcpwire.SupportedProtocolVersions[0]) {
		t.Errorf("MCP-Protocol-Version header = %q; the negotiated revision must be visible on the transport too", got)
	}
	// A session IS minted: the handshake succeeded. It is the client's move now.
	if rec.Header().Get(mcpwire.HeaderSessionID) == "" {
		t.Error("a successful handshake must mint a session id")
	}
}

// TestFence_1F5b_UnsupportedProtocolHeaderIsRefusedWith400.
//
// The transport spec keeps a refusal path, just at a different layer:
// "If the server receives a request with an invalid or unsupported
// MCP-Protocol-Version, it MUST respond with 400 Bad Request."
//
// This is where the frozen MCP_PROTOCOL_UNSUPPORTED code lives now.
func TestFence_1F5b_UnsupportedProtocolHeaderIsRefusedWith400(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	rec, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		map[string]string{mcpwire.HeaderProtocolVersion: "2099-01-01"})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 for an unsupported MCP-Protocol-Version header", rec.Code)
	}
	if got := aikeyCode(t, env); got != string(mcpwire.ErrProtocolUnsupported) {
		t.Errorf("aikey_code = %q, want MCP_PROTOCOL_UNSUPPORTED", got)
	}
	var d errorData
	if err := json.Unmarshal(env.Error.Data, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.SupportedVersions) != len(mcpwire.SupportedProtocolVersions) {
		t.Errorf("the refusal must list the support set, got %v", d.SupportedVersions)
	}
}

// TestAbsentProtocolHeaderAssumes2025_03_26 — the spec's backwards-compat rule.
//
// 🔴 Not "assume our newest": the header was introduced later, so a client that
// omits it is BY DEFINITION an older one, and assuming our newest would
// attribute newer semantics to a client that cannot have meant them.
func TestAbsentProtocolHeaderAssumes2025_03_26(t *testing.T) {
	v, ok := CheckProtocolVersionHeader("")
	if !ok {
		t.Fatal("an absent MCP-Protocol-Version header must be accepted")
	}
	if v != mcpwire.ProtocolV20250326 {
		t.Errorf("assumed %q for an absent header, spec says 2025-03-26", v)
	}
}

// TestNegotiationNeverUpgradesAPinnedClient — a client that pinned an older
// revision pinned it for a reason; answering with a newer one is how a client
// ends up parsing fields it does not understand.
func TestNegotiationNeverUpgradesAPinnedClient(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken, initializeBody("2024-11-05"), nil)
	var res mcpwire.InitializeResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatalf("%v (error=%+v)", err, env.Error)
	}
	if res.ProtocolVersion != "2024-11-05" {
		t.Errorf("client pinned 2024-11-05 but the gateway answered %q", res.ProtocolVersion)
	}
}

// TestCapabilitiesMatchesNegotiator is requirement R1's identity check: the
// DOCUMENTED support set and the ENFORCED support set must be the same set.
//
// A document that can disagree with behaviour is worse than no document,
// because people trust it.
func TestCapabilitiesMatchesNegotiator(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	req := httptest.NewRequest(http.MethodGet, "/mcp/capabilities", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var doc CapabilitiesDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.ProtocolVersions) == 0 {
		t.Fatal("/mcp/capabilities advertised no protocol versions")
	}
	for _, v := range doc.ProtocolVersions {
		// Every ADVERTISED revision must actually negotiate.
		if !Negotiate(mcpwire.ProtocolVersion(v)).OK {
			t.Errorf("capabilities advertises %q but the negotiator refuses it", v)
		}
		// And it must actually work end to end.
		r, e := rpc(t, mux, "/mcp/"+testToolset, testToken, initializeBody(v), nil)
		if r.Code != http.StatusOK || e.Error != nil {
			t.Errorf("advertised revision %q failed a real handshake: %d %+v", v, r.Code, e.Error)
		}
	}
	// 🔴 A revision that is NOT advertised must be answered with an advertised
	// one, and must be MARKED as downgraded. The marking is what keeps this
	// from being the silent downgrade R1 forbids: without it, "we spoke 2025-06-18"
	// and "they asked for something else and we substituted" would be
	// indistinguishable in both the response and the logs.
	neg := Negotiate("2099-01-01")
	if !neg.Downgraded {
		t.Error("an unadvertised revision was substituted without being marked as downgraded")
	}
	if !mcpwire.IsSupported(neg.Agreed) {
		t.Errorf("negotiator agreed on %q, which is not in the advertised set", neg.Agreed)
	}
}

// TestCapabilitiesDoesNotClaimOAuth — tasks 1.8b. Shipping two RFC 9728
// endpoints is not OAuth 2.1 support, and this document is quoted in sales
// conversations.
func TestCapabilitiesDoesNotClaimOAuth(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	req := httptest.NewRequest(http.MethodGet, "/mcp/capabilities", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var doc CapabilitiesDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Features["oauth_authorization_server"] {
		t.Error("capabilities claims OAuth authorization-server support; the gateway only serves protected-resource metadata")
	}
	// Capabilities not yet built must not be advertised as built.
	//
	// 🔴 This list is the FENCE'S OWN, deliberately independent of
	// featuresNotYetShipped, and the first draft of this test got it wrong in an
	// instructive way: it iterated the production map, so DELETING an entry
	// promoted a capability to "available" with nothing left to object. A drill
	// caught it — the over-claim direction was unfalsifiable.
	//
	// Two directions, two guards:
	//   over-claim   this list, independent, plus a subset check so the
	//                production map cannot quietly drop one
	//   under-claim  derived from the map (below), because THAT direction is
	//                what actually went wrong three times
	for _, unbuilt := range []string{"rate_limiting", "oauth_authorization_server"} {
		if doc.Features[unbuilt] {
			t.Errorf("capabilities advertises %q, which has not shipped. Sales quotes this "+
				"document; a true here is a promise nobody agreed to make.", unbuilt)
		}
		if _, declared := featuresNotYetShipped[unbuilt]; !declared {
			t.Errorf("%q was removed from featuresNotYetShipped but this fence still lists it "+
				"as unbuilt. If it really shipped, move it to the shipped list below in the "+
				"SAME change — that is the deliberate act this pair exists to require.", unbuilt)
		}
	}
	// Every not-yet entry must carry a REASON a reader can act on. An empty
	// string would make the map a list again.
	for name, why := range featuresNotYetShipped {
		if strings.TrimSpace(why) == "" {
			t.Errorf("featuresNotYetShipped[%q] has no reason; a client told 'false' with no "+
				"explanation cannot tell 'not built' from 'broken'", name)
		}
	}
	// The other direction: a feature that HAS shipped must be advertised.
	// Without this half, the list above can only ever catch over-claiming, and
	// under-claiming is what actually happened.
	// 🔴 call_audit is in this list as of P12. P7 shipped it and nothing flipped
	// the flag — the third occurrence of the drift this fence exists to catch,
	// and the reason the document is now COMPUTED from featuresNotYetShipped.
	for _, shipped := range []string{"tool_grants", "manifest_drift_freeze", "managed_backend_creds",
		"stdio_backends", "call_audit"} {
		if !doc.Features[shipped] {
			t.Errorf("capabilities reports %q as unavailable, but it shipped; a client that "+
				"reads this document to decide whether to rely on the feature will skip it", shipped)
		}
	}
}

// ---------------------------------------------------------------------------
// Fence 1.F2 — a panic in an MCP handler must not reach the shared server
// ---------------------------------------------------------------------------

// TestFence_1F2_PanicInMcpHandlerIsContained.
//
// 🔴 This is the acceptance criterion for the DEPLOYMENT SHAPE, not a nicety.
// The MCP plane shares a process with LLM forwarding because splitting them
// would double the credential surface; that trade is only defensible if a fault
// here cannot reach there.
func TestFence_1F2_PanicInMcpHandlerIsContained(t *testing.T) {
	iso := NewIsolation(4, nil, discardLogger())

	llmServed := 0
	mux := http.NewServeMux()
	mux.Handle("POST /mcp/boom", iso.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("simulated defect inside an MCP handler")
	})))
	mux.HandleFunc("POST /v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		llmServed++
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	// If the panic escaped, this call itself would panic and fail the test.
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("contained panic answered %d, want 500", rec.Code)
	}
	// 🔴 It must NOT be reported as an upstream failure: a panic is our defect,
	// and an EXT_ code would send the customer to debug their own MCP server.
	if strings.Contains(rec.Body.String(), "EXT_") {
		t.Errorf("a panic was blamed on the upstream: %s", rec.Body)
	}

	// The LLM plane keeps serving afterwards, in the same process.
	llmRec := httptest.NewRecorder()
	mux.ServeHTTP(llmRec, httptest.NewRequest(http.MethodPost, "/v1/messages", nil))
	if llmRec.Code != http.StatusOK || llmServed != 1 {
		t.Fatalf("LLM plane degraded after an MCP panic: code=%d served=%d", llmRec.Code, llmServed)
	}

	if got := iso.Stats().PanicsRecovered; got != 1 {
		t.Errorf("PanicsRecovered = %d, want 1 — a contained panic must stay visible", got)
	}
}

// TestContainedPanicDegradesHealth — the shell's job is to keep the LLM path
// alive, not to make an MCP defect invisible.
func TestContainedPanicDegradesHealth(t *testing.T) {
	mux, h := newTestServer(t, fixtureTools())
	// Reach into the same isolation instance the routes were built with.
	panicMux := http.NewServeMux()
	panicMux.Handle("POST /boom", h.iso.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("x")
	})))
	panicMux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/boom", nil))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/mcp", nil))
	var doc HealthDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Status != PlaneDegraded {
		t.Errorf("health status = %q after a contained panic, want %q", doc.Status, PlaneDegraded)
	}
	if doc.Reason == "" {
		t.Error("a degraded plane must say why")
	}
	if doc.Plane.PanicsRecovered != 1 {
		t.Errorf("health reported %d panics, want 1", doc.Plane.PanicsRecovered)
	}
}

// ---------------------------------------------------------------------------
// Fence 1.F3 — MCP saturation must not reach the LLM plane
// ---------------------------------------------------------------------------

// TestFence_1F3_SaturatedMcpPlaneShedsAndLeavesLlmAlone.
//
// Simulates the goroutine-leak / slow-upstream case: MCP handlers that never
// return. Once the private budget is gone, new MCP requests are SHED, and the
// LLM plane is untouched.
func TestFence_1F3_SaturatedMcpPlaneShedsAndLeavesLlmAlone(t *testing.T) {
	const limit = 3
	iso := NewIsolation(limit, nil, discardLogger())

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	// 🔴 Unblock the wedged handlers no matter how this test exits. Without
	// this, a FAILING run (which is what a fence drill deliberately produces)
	// leaves three handlers parked forever and the drill HANGS instead of
	// reporting red — a fence you cannot run is not a fence.
	defer releaseAll()

	var wg sync.WaitGroup

	mux := http.NewServeMux()
	mux.Handle("POST /mcp/slow", iso.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})))
	llmServed := make(chan struct{}, 1)
	mux.HandleFunc("POST /v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		llmServed <- struct{}{}
		w.WriteHeader(http.StatusOK)
	})

	// Fill every slot.
	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/mcp/slow", nil))
		}()
	}
	waitFor(t, func() bool { return iso.Stats().InFlight == limit })

	// The next MCP request is shed — PROMPTLY, not queued.
	//
	// 🔴 The promptness is asserted, not assumed. A shell that queued instead
	// of shedding would still eventually answer, and a fence that waits for it
	// would pass while the isolation guarantee was gone: the whole point is
	// that a saturated plane costs a new request nothing.
	shed := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		mux.ServeHTTP(shed, httptest.NewRequest(http.MethodPost, "/mcp/slow", nil))
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		releaseAll()
		t.Fatal("a request arriving at a saturated plane was QUEUED, not shed; the concurrency budget is not being enforced")
	}
	if shed.Code != http.StatusTooManyRequests {
		t.Fatalf("saturated plane answered %d, want 429", shed.Code)
	}
	if !strings.Contains(shed.Body.String(), string(mcpwire.ErrRateLimited)) {
		t.Errorf("shed request should carry MCP_RATE_LIMITED: %s", shed.Body)
	}
	if got := iso.Stats().Rejected; got != 1 {
		t.Errorf("Rejected = %d, want 1 — shedding must be counted, not silent", got)
	}

	// 🔴 The whole point: LLM forwarding is unaffected while MCP is wedged.
	llmRec := httptest.NewRecorder()
	mux.ServeHTTP(llmRec, httptest.NewRequest(http.MethodPost, "/v1/messages", nil))
	if llmRec.Code != http.StatusOK {
		t.Fatalf("LLM plane answered %d while the MCP plane was saturated", llmRec.Code)
	}
	select {
	case <-llmServed:
	default:
		t.Fatal("the LLM handler never ran while the MCP plane was saturated")
	}

	releaseAll()
	wg.Wait()
	waitFor(t, func() bool { return iso.Stats().InFlight == 0 })
}

// TestConcurrencySlotIsReleasedOnPanic — a leaked slot would permanently shrink
// the budget, so the first panic would slowly wedge the plane shut over time.
func TestConcurrencySlotIsReleasedOnPanic(t *testing.T) {
	iso := NewIsolation(1, nil, discardLogger())
	h := iso.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("x") }))

	for i := 0; i < 3; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil))
	}
	if got := iso.Stats().InFlight; got != 0 {
		t.Fatalf("InFlight = %d after panics; the semaphore slot leaked", got)
	}
	if got := iso.Stats().Rejected; got != 0 {
		t.Errorf("Rejected = %d; panicking handlers must not consume the budget permanently", got)
	}
}

// TestTimeoutCoversWorkNotQueueing pins the ordering in Wrap: the deadline
// starts when work starts. If the timeout wrapped semaphore acquisition
// instead, every request queued under load would fail with a timeout that has
// nothing to do with the upstream — and the logs would blame the backend.
func TestTimeoutCoversWorkNotQueueing(t *testing.T) {
	iso := NewIsolation(1, nil, discardLogger())

	started := make(chan struct{})
	release := make(chan struct{})
	var deadlineOK bool

	h := iso.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dl, ok := r.Context().Deadline()
		// The deadline must be ~the full timeout away, measured from NOW —
		// i.e. not eroded by however long this request waited for a slot.
		deadlineOK = ok && time.Until(dl) > iso.Timeout()-time.Second
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))

	go h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil))
	<-started
	close(release)
	waitFor(t, func() bool { return iso.Stats().InFlight == 0 })

	if !deadlineOK {
		t.Error("the request deadline did not cover the full timeout; it appears to include queueing time")
	}
}

// ---------------------------------------------------------------------------
// sessions
// ---------------------------------------------------------------------------

// TestSessionFromAnotherToolsetIsRejected — a session opened against one
// toolset must not be usable to read another.
func TestSessionFromAnotherToolsetIsRejected(t *testing.T) {
	h := NewHandler(Config{
		Catalog: &StaticCatalog{Toolsets: map[string]ToolsetView{
			"alpha": {Slug: "alpha", Tools: fixtureTools()},
			"beta":  {Slug: "beta", Tools: nil},
		}},
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(8, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	rec, _ := rpc(t, mux, "/mcp/alpha", testToken, initializeBody("2025-06-18"), nil)
	sid := rec.Header().Get(mcpwire.HeaderSessionID)
	if sid == "" {
		t.Fatal("no session minted")
	}

	_, env := rpc(t, mux, "/mcp/beta", testToken, `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`,
		map[string]string{mcpwire.HeaderSessionID: sid})
	if got := aikeyCode(t, env); got != string(mcpwire.ErrSessionNotFound) {
		t.Errorf("cross-toolset session reuse produced %q, want MCP_SESSION_NOT_FOUND", got)
	}
}

// TestMissingSessionHeaderIsToleratedForOlderRevisions — 2024-11-05 has no
// session header at all; rejecting those clients would undo R1's compatibility.
func TestMissingSessionHeaderIsToleratedForOlderRevisions(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	if env.Error != nil {
		t.Errorf("tools/list without a session header should work, got %+v", env.Error)
	}
}

// TestDeleteSessionIsIdempotent — a client retrying after a dropped response
// must not be told it failed at the thing it already succeeded at.
func TestDeleteSessionIsIdempotent(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodDelete, "/mcp/"+testToolset, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set(mcpwire.HeaderSessionID, "never-existed")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("DELETE attempt %d returned %d, want 204", i+1, rec.Code)
		}
	}
}

// TestSessionIdsAreUnguessable — a sequential or time-derived id would let a
// client that holds one id probe for others.
func TestSessionIdsAreUnguessable(t *testing.T) {
	store := NewSessionStore(0)
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		s, err := store.Create("t", testOrg, testSeat, mcpwire.ProtocolV20250618, mcpwire.Implementation{})
		if err != nil {
			t.Fatal(err)
		}
		if len(s.ID) < 40 {
			t.Fatalf("session id is only %d chars; that is guessable", len(s.ID))
		}
		if seen[s.ID] {
			t.Fatal("session id collision — ids are not random")
		}
		seen[s.ID] = true
	}
}

// TestExpiredSessionIsIndistinguishableFromUnknown — both mean "run initialize
// again", and distinguishing them tells a prober which ids once existed.
func TestExpiredSessionIsIndistinguishableFromUnknown(t *testing.T) {
	store := NewSessionStore(time.Minute)
	now := time.Now()
	store.now = func() time.Time { return now }

	s, err := store.Create("t", testOrg, testSeat, mcpwire.ProtocolV20250618, mcpwire.Implementation{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get(s.ID); !ok {
		t.Fatal("fresh session not found")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := store.Get(s.ID); ok {
		t.Error("an idle session past its timeout must be gone")
	}
	if _, ok := store.Get("never-existed"); ok {
		t.Error("unknown session id resolved")
	}
}

// ---------------------------------------------------------------------------
// tenancy + tool visibility
// ---------------------------------------------------------------------------

// TestUnknownToolsetDoesNotRevealExistence — answering "exists but not yours"
// tells a caller that a toolset by that name exists in another org.
func TestUnknownToolsetDoesNotRevealExistence(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	rec, _ := rpc(t, mux, "/mcp/somebody-elses", testToken, initializeBody("2025-06-18"), nil)
	body := rec.Body.String()
	if strings.Contains(strings.ToLower(body), "another organization") ||
		strings.Contains(strings.ToLower(body), "not authorized to see") {
		t.Errorf("the not-found reply leaks that the toolset exists elsewhere: %s", body)
	}
}

// TestCallingAnUngrantedToolIsForbiddenNotUnknown — a tool the seat cannot use
// must not be discoverable by probing names.
func TestCallingAnUngrantedToolIsForbiddenNotUnknown(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_everything","arguments":{}}}`, nil)
	if got := aikeyCode(t, env); got != string(mcpwire.ErrToolForbidden) {
		t.Errorf("aikey_code = %q, want MCP_TOOL_FORBIDDEN", got)
	}
}

// TestACatalogThatCannotAuthoriseRefusesEveryCall.
//
// 🔴 CHANGED IN P2, and the change is the point. In P1 this asserted
// MCP_BACKEND_UNAVAILABLE, because the placeholder catalog had no notion of
// grants and every call was simply unroutable. P2 introduced the CallResolver
// seam, and a catalog that does not implement it — StaticCatalog, the test
// fixture — can no longer authorise anything.
//
// The correct behaviour for "I cannot evaluate whether you are allowed" is to
// REFUSE. Failing open here would mean that the day someone wires a catalog
// without a resolver, every seat silently gets every tool.
func TestACatalogThatCannotAuthoriseRefusesEveryCall(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"query_readonly","arguments":{"sql":"select 1"}}}`, nil)
	if got := aikeyCode(t, env); got != string(mcpwire.ErrToolForbidden) {
		t.Errorf("aikey_code = %q, want MCP_TOOL_FORBIDDEN — a catalog that cannot answer "+
			"\"may this seat run this\" has not said yes", got)
	}
}

// ---------------------------------------------------------------------------
// protocol hygiene
// ---------------------------------------------------------------------------

func TestMalformedBodyDoesNotEchoItsContent(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	secret := "sk-live-DO-NOT-ECHO-THIS"
	rec, _ := rpc(t, mux, "/mcp/"+testToolset, testToken, "not json at all "+secret, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Errorf("the parse error echoed the request body: %s", rec.Body)
	}
}

func TestOversizedBodyIsRefusedWithoutBuffering(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	big := strings.Repeat("a", maxRequestBody+100)
	rec, _ := rpc(t, mux, "/mcp/"+testToolset, testToken, `{"jsonrpc":"2.0","id":1,"method":"ping","params":"`+big+`"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized body returned %d, want 400", rec.Code)
	}
}

func TestWrongJsonrpcVersionIsRefused(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	rec, _ := rpc(t, mux, "/mcp/"+testToolset, testToken, `{"jsonrpc":"1.0","id":1,"method":"ping"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rec.Code)
	}
}

func TestUnknownMethodNamesTheSupportedSet(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken, `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`, nil)
	if env.Error == nil || env.Error.Code != mcpwire.CodeMethodNotFound {
		t.Fatalf("want method-not-found, got %+v", env.Error)
	}
	if !strings.Contains(env.Error.Message, "tools/list") {
		t.Errorf("the error should name what IS supported: %q", env.Error.Message)
	}
}

// TestSseChannelExistsAndStreams — a 404/405 here is read by several clients as
// "this server is broken" and aborts a session that was about to work.
func TestSseChannelExistsAndStreams(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())

	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/mcp/"+testToolset, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SSE channel returned %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	buf := make([]byte, 32)
	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("reading the opening frame: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), ":") {
		t.Errorf("expected an opening comment frame to flush headers, got %q", string(buf[:n]))
	}
}

// ---------------------------------------------------------------------------
// health
// ---------------------------------------------------------------------------

// TestHealthIsSeparateFromOverallHealth — folding MCP trouble into /health
// would page someone to investigate LLM forwarding that is perfectly fine.
func TestHealthIsSeparateFromOverallHealth(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/mcp", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/health/mcp returned %d", rec.Code)
	}
	var doc HealthDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Status != PlaneHealthy {
		t.Errorf("status = %q on a quiet plane", doc.Status)
	}
	if doc.ToolsetCount != 1 {
		t.Errorf("toolset_count = %d, want 1", doc.ToolsetCount)
	}
	if len(doc.ProtocolVersions) != len(mcpwire.SupportedProtocolVersions) {
		t.Errorf("health must report the same support set as capabilities")
	}
	// 🔴 Not-yet-tracked sections must be ABSENT, not zero: "0 tools need
	// review" and "review state is not tracked yet" are different claims, and a
	// release gate asserting the first while receiving the second asserts on
	// nothing.
	if doc.ToolsNeedingReview != nil {
		t.Error("tools_needing_review is reported before P3 tracks it")
	}
	if doc.PolicyAgeSeconds != nil {
		t.Error("policy_age_seconds is reported before P2 tracks it")
	}
	if strings.Contains(rec.Body.String(), `"tools_needing_review":0`) {
		t.Error("an untracked field is being serialised as 0")
	}
}

// TestHealthNeedsNoBearer — an operator diagnosing a broken gateway must not
// need a working credential to read its health.
func TestHealthNeedsNoBearer(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/mcp", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/health/mcp required auth (%d); it must stay readable during an incident", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not reached within 3s")
}

// TestIsolationTimeoutTracksLivePolicy — the org's fallback policy arrives on
// the 60s poll, AFTER the listener is already serving. A timeout captured at
// construction would be the builtin default forever, so an admin who later set
// one would see the console accept it and the gateway silently ignore it.
func TestIsolationTimeoutTracksLivePolicy(t *testing.T) {
	var current fallbackpolicy.Effective
	current = fallbackpolicy.Resolve(nil, fallbackpolicy.LocalOverrides{})
	iso := NewIsolation(4, func() fallbackpolicy.Effective { return current }, discardLogger())

	builtin := iso.Timeout()
	if got := iso.Stats().TimeoutSource; got != string(fallbackpolicy.SourceBuiltin) {
		t.Errorf("initial timeout source = %q, want %q", got, fallbackpolicy.SourceBuiltin)
	}

	// The control plane answers, mid-life.
	ms := int64(1234)
	current = fallbackpolicy.Resolve(&fallbackpolicy.Policy{UpstreamAttemptTimeoutMs: &ms}, fallbackpolicy.LocalOverrides{})

	if got := iso.Timeout(); got != 1234*time.Millisecond {
		t.Errorf("timeout = %v after the org policy arrived, want 1.234s (was %v)", got, builtin)
	}
	if got := iso.Stats().TimeoutSource; got != string(fallbackpolicy.SourceOrg) {
		t.Errorf("timeout source = %q, want %q — provenance must follow the value", got, fallbackpolicy.SourceOrg)
	}
}

// TestExplicitZeroTimeoutGetsAFloorAndSaysSo — an admin choosing "no ceiling"
// for the LLM path cannot be honoured here, because an unbounded MCP request
// holds one of a finite number of plane slots. The floor is applied and the
// source string admits it rather than pretending the 0 was never set.
func TestExplicitZeroTimeoutGetsAFloorAndSaysSo(t *testing.T) {
	zero := int64(0)
	eff := fallbackpolicy.Resolve(&fallbackpolicy.Policy{UpstreamAttemptTimeoutMs: &zero}, fallbackpolicy.LocalOverrides{})
	iso := NewIsolation(4, func() fallbackpolicy.Effective { return eff }, discardLogger())

	if got := iso.Timeout(); got != DefaultPlaneTimeout {
		t.Errorf("timeout = %v for an explicit 0, want the MCP floor %v", got, DefaultPlaneTimeout)
	}
	src := iso.Stats().TimeoutSource
	if !strings.Contains(src, "mcp_floor") {
		t.Errorf("source = %q; applying a floor must be visible, not silent", src)
	}
	if !strings.HasPrefix(src, string(fallbackpolicy.SourceOrg)) {
		t.Errorf("source = %q; it must still name the layer the admin actually set", src)
	}
}

// ---------------------------------------------------------------------------
// DNS-rebinding defence (spec MUST) — see origin.go
// ---------------------------------------------------------------------------

// TestFence_BrowserOriginIsRefused.
//
// 🔴 Not a generic web hardening item for THIS product. The gateway exists to
// hold the customer's GitHub PATs and database passwords so the developer's
// machine does not have to. A rebinding hole would let any web page the
// developer visits drive those credentials — reintroducing, through the
// browser, exactly the exposure the product removes.
func TestFence_BrowserOriginIsRefused(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())

	for _, origin := range []string{
		"https://evil.example.com",
		"http://attacker.test",
		"null", // sandboxed iframe / file:// page — unattributable
	} {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp/"+testToolset, strings.NewReader(initializeBody("2025-06-18")))
			req.Header.Set("Authorization", "Bearer "+testToken)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("Origin %q got %d, want 403", origin, rec.Code)
			}
			// 🔴 The refusal must not teach a prober what WOULD be accepted.
			body := strings.ToLower(rec.Body.String())
			for _, leak := range []string{"127.0.0.1", "localhost", "loopback"} {
				if strings.Contains(body, leak) {
					t.Errorf("the refusal body names the accepted origins (%q): %s", leak, rec.Body)
				}
			}
		})
	}
}

// TestLoopbackAndAbsentOriginsAreAccepted — rejecting absent-Origin requests
// would break every real MCP client (they are not browsers and send none) while
// stopping no attack. The asymmetry IS the mitigation.
func TestLoopbackAndAbsentOriginsAreAccepted(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())

	for _, origin := range []string{"", "http://localhost:3000", "http://127.0.0.1:27200", "http://[::1]:8080"} {
		name := origin
		if name == "" {
			name = "(absent)"
		}
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp/"+testToolset, strings.NewReader(initializeBody("2025-06-18")))
			req.Header.Set("Authorization", "Bearer "+testToken)
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("Origin %q got %d, want 200", name, rec.Code)
			}
		})
	}
}

// TestOriginIsCheckedBeforeAuthentication — a rebinding attempt must be refused
// without the gateway working on its behalf, and the reply must not vary by
// whether the attacker's credentials happened to be valid (which would make the
// endpoint a credential oracle).
func TestOriginIsCheckedBeforeAuthentication(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())

	withGoodToken := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/mcp/"+testToolset, strings.NewReader(initializeBody("2025-06-18")))
	r1.Header.Set("Origin", "https://evil.example.com")
	r1.Header.Set("Authorization", "Bearer "+testToken)
	mux.ServeHTTP(withGoodToken, r1)

	withNoToken := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/mcp/"+testToolset, strings.NewReader(initializeBody("2025-06-18")))
	r2.Header.Set("Origin", "https://evil.example.com")
	mux.ServeHTTP(withNoToken, r2)

	if withGoodToken.Code != http.StatusForbidden || withNoToken.Code != http.StatusForbidden {
		t.Fatalf("both must be 403: with-token=%d without-token=%d", withGoodToken.Code, withNoToken.Code)
	}
	if withGoodToken.Body.String() != withNoToken.Body.String() {
		t.Error("the rebinding refusal differs by credential validity, making the endpoint a credential oracle")
	}
}

// ---------------------------------------------------------------------------
// session termination status (spec MUST)
// ---------------------------------------------------------------------------

// TestFence_UnknownSessionGets404SoClientsReinitialize.
//
// 🔴 The status code is load-bearing: "When a client receives HTTP 404 in
// response to a request containing an Mcp-Session-Id, it MUST start a new
// session by sending a new InitializeRequest."
//
// Answering 200 + an error body looks interoperable and is functionally dead —
// the client never learns to re-initialize, so a proxy restart leaves every
// connected client permanently broken until a human restarts it too.
func TestFence_UnknownSessionGets404SoClientsReinitialize(t *testing.T) {
	mux, _ := newTestServer(t, fixtureTools())
	rec, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		map[string]string{mcpwire.HeaderSessionID: "a-session-from-a-previous-process"})

	if rec.Code != http.StatusNotFound {
		t.Fatalf("got HTTP %d for an unknown session; the spec requires 404 so the client re-initializes", rec.Code)
	}
	if got := aikeyCode(t, env); got != string(mcpwire.ErrSessionNotFound) {
		t.Errorf("aikey_code = %q, want MCP_SESSION_NOT_FOUND", got)
	}
}
