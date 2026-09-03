package mcp

// upstream_test.go — P3's proxy-side fences.
//
// The two that carry the most weight:
//
//	3.F2  the health probe must be tools/list and NOTHING else. Probing with a
//	      real tool installs a machine that acts on the customer's systems on a
//	      timer, forever, that nobody asked for.
//	D-13  no X-Aikey-* header may ever reach a third-party MCP server.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// recordingUpstream is a fake MCP server that records every method it is asked
// for, so a test can assert on what the gateway DID NOT call.
type recordingUpstream struct {
	mu      sync.Mutex
	methods []string
	headers []http.Header
	// reply, when set, overrides the default tools/list answer.
	reply func(method string) (any, *mcpwire.RPCError)
	// status, when non-zero, is returned instead of a JSON-RPC reply.
	status int
	// sse makes the server answer with an event stream.
	sse bool
	// delay simulates a slow upstream.
	delay time.Duration
	// onCallArgs, when set, receives the raw `arguments` of each tools/call.
	// Used by the compliance fences to prove what actually left the gateway —
	// asserting on the gateway's own view would let a mask that was recorded but
	// never applied pass.
	onCallArgs func(raw json.RawMessage)
}

func (u *recordingUpstream) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env mcpwire.Envelope
		_ = json.Unmarshal(body, &env)

		u.mu.Lock()
		u.methods = append(u.methods, env.Method)
		u.headers = append(u.headers, r.Header.Clone())
		onArgs := u.onCallArgs
		u.mu.Unlock()
		if onArgs != nil && env.Method == mcpwire.MethodToolsCall {
			var call mcpwire.CallToolRequest
			if err := json.Unmarshal(env.Params, &call); err == nil {
				onArgs(call.Arguments)
			}
		}

		if u.delay > 0 {
			time.Sleep(u.delay)
		}
		if u.status != 0 {
			w.WriteHeader(u.status)
			return
		}

		var result any
		var rpcErr *mcpwire.RPCError
		if u.reply != nil {
			result, rpcErr = u.reply(env.Method)
		} else {
			result = mcpwire.ListToolsResult{Tools: []mcpwire.Tool{{
				Name: "query_readonly", Description: "Run a read-only SQL query.",
				InputSchema: json.RawMessage(`{"type":"object"}`),
			}}}
		}
		raw, _ := json.Marshal(result)
		out := mcpwire.Envelope{JSONRPC: mcpwire.JSONRPCVersion, ID: env.ID, Result: raw, Error: rpcErr}
		if rpcErr != nil {
			out.Result = nil
		}
		payload, _ := json.Marshal(out)

		if u.sse {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			// A progress notification first, then the real answer — the shape a
			// spec-compliant Streamable HTTP server may produce.
			_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n")
			_, _ = io.WriteString(w, "event: message\ndata: "+string(payload)+"\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
}

func (u *recordingUpstream) calledMethods() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.methods...)
}

func (u *recordingUpstream) lastHeaders() http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.headers) == 0 {
		return nil
	}
	return u.headers[len(u.headers)-1]
}

// ---------------------------------------------------------------------------
// Fence 3.F2 — tools/list is the ONLY probe
// ---------------------------------------------------------------------------

// TestFence_3F2_TheHealthProbeCallsToolsListAndNothingElse.
//
// 🔴 Not squeamishness about side effects in the abstract: a probe runs on a
// TIMER. Probing with a real tool installs a machine that performs an action on
// the customer's systems every N seconds, forever, that nobody asked for and
// that no audit trail attributes to a person. If that tool writes, it is worse
// than a bug.
func TestFence_3F2_TheHealthProbeCallsToolsListAndNothingElse(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	store := NewPolicyStore()
	store.Store(&Policy{
		OrgID: testOrg, Version: 1,
		Backends: []PolicyBackend{{
			ID: "b1", Name: "github", Transport: TransportStreamableHTTP,
			EndpointURL: srv.URL, Status: "active",
		}},
	})
	syncer := NewManifestSyncer(testOrg, store, nil, nil, nil, discardLogger())
	syncer.SyncOnce(context.Background())

	methods := up.calledMethods()
	if len(methods) == 0 {
		t.Fatal("the syncer never contacted the backend")
	}
	for _, m := range methods {
		if m != mcpwire.MethodToolsList {
			t.Errorf("the manifest probe called %q. It may call tools/list and NOTHING else — "+
				"a probe runs on a timer, so any other method installs a machine that acts on "+
				"the customer's systems forever, unattributed.", m)
		}
	}
}

// TestFence_D13_NoAikeyHeaderReachesAnUpstreamMCPServer.
//
// 🔴 The rule already exists for LLM upstreams (a non-standard header is a
// persona signal that walls WAFs). It applies here for a wider reason: a
// third-party MCP server can sit behind any gateway, and we cannot predict what
// an unknown header does to it. Provenance travels in the RESPONSE direction and
// into the call record, never on the request.
func TestFence_D13_NoAikeyHeaderReachesAnUpstreamMCPServer(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	transport, _ := LookupTransport(TransportStreamableHTTP)
	// Simulate a future change that adds provenance headers on the way out.
	// The stripper must remove them regardless of name, which is why it works by
	// PREFIX — a list of known names is one forgotten entry from a leak.
	// 🔴 The injector is placed ABOVE the stripper — i.e. it runs FIRST and the
	// stripper still has to catch it. That models the real risk: an egress
	// wrapper, a tracing library, or any middleware added later sits between the
	// request builder and the wire, and a stripper that only runs in the builder
	// would be bypassed by all of them.
	original := upstreamHTTPClient.Transport
	upstreamHTTPClient.Transport = &headerStripper{next: headerInjector{
		next: original,
		inject: map[string]string{
			"X-Aikey-Seat-Id":  "seat_7",
			"X-Aikey-Trace-Id": "trace_abc",
			"x-aikey-org":      "org_42",
		},
	}}
	defer func() { upstreamHTTPClient.Transport = original }()

	if _, err := transport.ListTools(context.Background(), UpstreamBackend{
		ID: "b1", Transport: TransportStreamableHTTP, EndpointURL: srv.URL,
	}); err != nil {
		t.Fatal(err)
	}

	for name := range up.lastHeaders() {
		if strings.HasPrefix(strings.ToLower(name), "x-aikey-") {
			t.Errorf("header %q reached a third-party MCP server. 🔴 No X-Aikey-* header may ever "+
				"go out to an upstream (D-13); provenance belongs in the call record, not on the wire.", name)
		}
	}
}

// headerInjector adds headers after the transport built the request, to prove
// the stripper is the LAST thing before the wire rather than a convention the
// request builder happens to follow.
type headerInjector struct {
	next   http.RoundTripper
	inject map[string]string
}

func (h headerInjector) RoundTrip(r *http.Request) (*http.Response, error) {
	for k, v := range h.inject {
		r.Header.Set(k, v)
	}
	next := h.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(r)
}

// ---------------------------------------------------------------------------
// transports
// ---------------------------------------------------------------------------

// TestBothRemoteTransportsAreRegistered — the capabilities document promises
// them, so they must exist.
func TestBothRemoteTransportsAreRegistered(t *testing.T) {
	for _, name := range []string{TransportStreamableHTTP, TransportHTTPSSE} {
		if _, ok := LookupTransport(name); !ok {
			t.Errorf("transport %q is advertised but not registered", name)
		}
	}
	// stdio landed in P5. The assertion FLIPPED (it previously required stdio to
	// be absent) rather than being deleted, because what it protects is not
	// "stdio is missing" but "the registry and the capabilities document agree".
	if _, ok := LookupTransport(TransportStdio); !ok {
		t.Error("stdio is not registered but /mcp/capabilities reports stdio_backends=true")
	}
}

// TestCapabilitiesTransportsComeFromTheRegistry closes the drift class that the
// previous version of the test above could only close for ONE name at a time.
//
// 🔴 Derived, not enumerated. The project rule on fences is explicit that a
// hand-maintained whitelist only protects the entries somebody remembered to
// add — and P5 is precisely the change that would have been forgotten, because
// registering a transport is one line in an init() nowhere near this document.
func TestCapabilitiesTransportsComeFromTheRegistry(t *testing.T) {
	registered := RegisteredTransports()
	if len(registered) == 0 {
		t.Fatal("no transports registered at all — every assertion below would pass vacuously")
	}
	mux, _ := newTestServer(t, fixtureTools())
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/mcp/capabilities", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("capabilities: %d", rr.Code)
	}
	var doc CapabilitiesDocument
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("capabilities body: %v", err)
	}
	got := map[string]bool{}
	for _, name := range doc.Transports {
		got[name] = true
	}
	for _, name := range registered {
		if !got[name] {
			t.Errorf("transport %q is registered — this build CAN reach it — but the "+
				"capabilities document does not advertise it, so a client that reads the "+
				"document will never use it", name)
		}
	}
	if len(doc.Transports) != len(registered) {
		t.Errorf("the capabilities document advertises %v but the build registers %v; "+
			"advertising a transport that is not registered answers every call to it with "+
			"an unroutable backend", doc.Transports, registered)
	}
}

// TestSSEReplyTakesTheLastEnvelopeNotTheFirst.
//
// Streamable HTTP lets a server send progress notifications before the answer.
// 🔴 Taking the first frame is a bug that only appears against servers that
// actually send progress — i.e. it passes every test written against a simple
// fake and fails in the field.
func TestSSEReplyTakesTheLastEnvelopeNotTheFirst(t *testing.T) {
	up := &recordingUpstream{sse: true}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	transport, _ := LookupTransport(TransportStreamableHTTP)
	tools, err := transport.ListTools(context.Background(), UpstreamBackend{
		ID: "b1", Transport: TransportStreamableHTTP, EndpointURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("SSE reply was not parsed: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "query_readonly" {
		t.Errorf("got %+v; the progress notification was taken as the answer", tools)
	}
}

// TestUpstreamErrorsCarryTheBlame — EXT_ is how a customer decides whether to
// open a ticket with us or with whoever runs their MCP server.
func TestUpstreamErrorsCarryTheBlame(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   mcpwire.ErrorCode
	}{
		{"500 from upstream", http.StatusInternalServerError, mcpwire.ErrUpstream5XX},
		{"502 from upstream", http.StatusBadGateway, mcpwire.ErrUpstream5XX},
		{"401 from upstream", http.StatusUnauthorized, mcpwire.ErrCredentialMissing},
		{"403 from upstream", http.StatusForbidden, mcpwire.ErrCredentialMissing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := &recordingUpstream{status: tc.status}
			srv := httptest.NewServer(up.handler())
			defer srv.Close()

			transport, _ := LookupTransport(TransportStreamableHTTP)
			_, err := transport.ListTools(context.Background(), UpstreamBackend{
				ID: "b1", Transport: TransportStreamableHTTP, EndpointURL: srv.URL,
			})
			var ue *UpstreamError
			if !asUpstream(err, &ue) {
				t.Fatalf("error is not an UpstreamError: %v", err)
			}
			if ue.Code != tc.want {
				t.Errorf("aikey_code = %q, want %q", ue.Code, tc.want)
			}
			// 🔴 A 401/403 is reported as a CREDENTIAL problem because that is
			// the one upstream status with an action the customer can take.
			if tc.want == mcpwire.ErrCredentialMissing && !strings.Contains(ue.Detail, "credential") {
				t.Errorf("the detail does not name the credential: %q", ue.Detail)
			}
		})
	}
}

// TestABackendWithAnUnresolvedCredentialIsRefusedNotTriedBare.
//
// 🔴 Sending a bare request to an endpoint that expects auth yields a 401 that
// reads like "the customer's token is wrong", sending them to rotate a
// credential that was never the problem.
func TestABackendWithAnUnresolvedCredentialIsRefusedNotTriedBare(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	transport, _ := LookupTransport(TransportStreamableHTTP)
	_, err := transport.ListTools(context.Background(), UpstreamBackend{
		ID: "b1", Transport: TransportStreamableHTTP, EndpointURL: srv.URL,
		CredentialID: "cred_1", // declared…
		// …and Credential is the zero value: nothing resolved.
	})
	if err == nil {
		t.Fatal("a backend with an unresolved credential was contacted anyway")
	}
	if len(up.calledMethods()) != 0 {
		t.Error("the request went out despite the missing credential; the resulting 401 would look like the customer's token is wrong")
	}
}

// TestCredentialIsAppliedButNeverLogged — R7's transport-level half.
func TestCredentialIsAppliedButNeverLogged(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	transport, _ := LookupTransport(TransportStreamableHTTP)
	if _, err := transport.ListTools(context.Background(), UpstreamBackend{
		ID: "b1", Transport: TransportStreamableHTTP, EndpointURL: srv.URL,
		CredentialID: "cred_1",
		Credential:   UpstreamCredential{Kind: "bearer", Secret: "ghp_SUPERSECRET"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := up.lastHeaders().Get("Authorization"); got != "Bearer ghp_SUPERSECRET" {
		t.Errorf("the credential was not applied: %q", got)
	}
	// 🔴 And the type itself has nowhere for it to leak from: no String(), no
	// JSON tags. A type that cannot be printed by accident beats a comment
	// asking people not to.
	blob, err := json.Marshal(UpstreamCredential{Kind: "bearer", Secret: "ghp_SUPERSECRET"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "SUPERSECRET") {
		t.Errorf("UpstreamCredential serialises its secret: %s", blob)
	}
}

// TestOversizedUpstreamResponseIsRefused — without a cap, a backend can make the
// proxy allocate without bound while holding one of the isolation shell's finite
// slots, turning the protection into the attack's amplifier.
func TestOversizedUpstreamResponseIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("a", 1<<20)
		for i := 0; i < 10; i++ {
			_, _ = io.WriteString(w, chunk)
		}
	}))
	defer srv.Close()

	transport, _ := LookupTransport(TransportStreamableHTTP)
	_, err := transport.ListTools(context.Background(), UpstreamBackend{
		ID: "b1", Transport: TransportStreamableHTTP, EndpointURL: srv.URL,
	})
	if err == nil {
		t.Fatal("an oversized upstream response was accepted")
	}
	if !strings.Contains(err.Error(), "ceiling") {
		t.Errorf("the refusal does not name the limit: %v", err)
	}
}

// ---------------------------------------------------------------------------
// backend health — the three-state rule
// ---------------------------------------------------------------------------

// TestABackendBelowTheFailureThresholdIsUnknownNotHealthy.
//
// 🔴 Leaving it "healthy" would let a backend that fails two probes out of every
// three read as fine. "We have not decided it is down" and "it is up" are
// different facts.
func TestABackendBelowTheFailureThresholdIsUnknownNotHealthy(t *testing.T) {
	up := &recordingUpstream{status: http.StatusInternalServerError}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	store := NewPolicyStore()
	store.Store(&Policy{OrgID: testOrg, Version: 1, Backends: []PolicyBackend{{
		ID: "b1", Name: "gh", Transport: TransportStreamableHTTP, EndpointURL: srv.URL, Status: "active",
	}}})
	syncer := NewManifestSyncer(testOrg, store, nil, nil, nil, discardLogger())

	syncer.SyncOnce(context.Background())
	if got := syncer.Status()["b1"].Health; got != BackendUnknown {
		t.Errorf("after ONE failure health = %q, want %q", got, BackendUnknown)
	}
	syncer.SyncOnce(context.Background())
	syncer.SyncOnce(context.Background())
	if got := syncer.Status()["b1"].Health; got != BackendCircuitOpen {
		t.Errorf("after THREE failures health = %q, want %q", got, BackendCircuitOpen)
	}
	// 🔴 And the cooldown is a NUMBER the caller can report. "Try again later"
	// without one makes a model retry immediately and forever.
	if syncer.CooldownRemaining("b1") <= 0 {
		t.Error("an open circuit reports no cooldown; MCP_BACKEND_UNAVAILABLE would carry no retry hint")
	}
}

// TestANeverProbedBackendIsUnknownNotHealthy — the three-state rule's first
// state. A backend nobody has checked must not render green.
func TestANeverProbedBackendIsUnknownNotHealthy(t *testing.T) {
	syncer := NewManifestSyncer(testOrg, NewPolicyStore(), nil, nil, nil, discardLogger())
	if got := syncer.statusFor("never-seen").Health; got != BackendUnknown {
		t.Errorf("a never-probed backend reports %q, want %q", got, BackendUnknown)
	}
}

// TestABackendNeedingACredentialIsUnknownWhenNoResolverExists.
//
// 🔴 Not "unhealthy": probing it unauthenticated would record a 401 as "this
// backend is broken", sending an operator to debug a server that is fine.
func TestABackendNeedingACredentialIsUnknownWhenNoResolverExists(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	store := NewPolicyStore()
	store.Store(&Policy{OrgID: testOrg, Version: 1, Backends: []PolicyBackend{{
		ID: "b1", Name: "gh", Transport: TransportStreamableHTTP, EndpointURL: srv.URL,
		CredentialID: "cred_1", Status: "active",
	}}})
	// nil resolver — the P3 state, before P4 ships.
	syncer := NewManifestSyncer(testOrg, store, nil, nil, nil, discardLogger())
	syncer.SyncOnce(context.Background())

	if got := syncer.Status()["b1"].Health; got != BackendUnknown {
		t.Errorf("health = %q, want %q", got, BackendUnknown)
	}
	if len(up.calledMethods()) != 0 {
		t.Error("the backend was probed without its credential; the 401 would be recorded as a backend fault")
	}
}

// TestADisabledBackendIsNotProbed — probing anyway keeps a disabled backend's
// health "fresh", which is the opposite of what disabling is for.
func TestADisabledBackendIsNotProbed(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	store := NewPolicyStore()
	store.Store(&Policy{OrgID: testOrg, Version: 1, Backends: []PolicyBackend{{
		ID: "b1", Name: "gh", Transport: TransportStreamableHTTP, EndpointURL: srv.URL,
		Status: StatusDisabled,
	}}})
	NewManifestSyncer(testOrg, store, nil, nil, nil, discardLogger()).SyncOnce(context.Background())

	if len(up.calledMethods()) != 0 {
		t.Error("a disabled backend was still probed")
	}
}

// TestTheSyncerReportsWhatItObserved — and the report carries the frozen hash
// algorithm's output, not something the syncer invented.
func TestTheSyncerReportsWhatItObserved(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	rep := &capturingReporter{}
	store := NewPolicyStore()
	store.Store(&Policy{OrgID: testOrg, Version: 1, Backends: []PolicyBackend{{
		ID: "b1", Name: "gh", Transport: TransportStreamableHTTP, EndpointURL: srv.URL, Status: "active",
	}}})
	NewManifestSyncer(testOrg, store, rep, nil, nil, discardLogger()).SyncOnce(context.Background())

	if len(rep.reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(rep.reports))
	}
	m := rep.reports[0]
	if m.BackendID != "b1" || len(m.Tools) != 1 {
		t.Fatalf("report is wrong: %+v", m)
	}
	// The hash must equal what the FROZEN algorithm produces for that tool —
	// not a value the syncer computed some other way.
	want, err := mcpwire.ManifestHash(mcpwire.Tool{
		Name: "query_readonly", Description: "Run a read-only SQL query.",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Tools[0].Hash != want {
		t.Errorf("reported hash %q, frozen algorithm produces %q", m.Tools[0].Hash, want)
	}
	if m.SetHash == "" {
		t.Error("no set hash was reported; a tool appearing or disappearing would go unnoticed")
	}
}

// TestAReportFailureDoesNotLookLikeABackendFailure — the two send an operator
// to different places.
func TestAReportFailureDoesNotLookLikeABackendFailure(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	store := NewPolicyStore()
	store.Store(&Policy{OrgID: testOrg, Version: 1, Backends: []PolicyBackend{{
		ID: "b1", Name: "gh", Transport: TransportStreamableHTTP, EndpointURL: srv.URL, Status: "active",
	}}})
	syncer := NewManifestSyncer(testOrg, store, failingReporter{}, nil, nil, discardLogger())
	syncer.SyncOnce(context.Background())

	if got := syncer.Status()["b1"].Health; got != BackendHealthy {
		t.Errorf("health = %q after a REPORTING failure; the backend answered fine and must read healthy", got)
	}
}

// TestDuplicateToolNamesUpstreamAreAFailureNotACollapse — collapsing would let
// an upstream hide a second, different definition behind a name we trust.
func TestDuplicateToolNamesUpstreamAreAFailureNotACollapse(t *testing.T) {
	up := &recordingUpstream{reply: func(string) (any, *mcpwire.RPCError) {
		return mcpwire.ListToolsResult{Tools: []mcpwire.Tool{
			{Name: "dup", Description: "a", InputSchema: json.RawMessage(`{}`)},
			{Name: "dup", Description: "b", InputSchema: json.RawMessage(`{}`)},
		}}, nil
	}}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	rep := &capturingReporter{}
	store := NewPolicyStore()
	store.Store(&Policy{OrgID: testOrg, Version: 1, Backends: []PolicyBackend{{
		ID: "b1", Name: "gh", Transport: TransportStreamableHTTP, EndpointURL: srv.URL, Status: "active",
	}}})
	syncer := NewManifestSyncer(testOrg, store, rep, nil, nil, discardLogger())
	syncer.SyncOnce(context.Background())

	if len(rep.reports) != 0 {
		t.Error("a manifest with duplicate tool names was reported; the duplicate would silently win")
	}
	if got := syncer.Status()["b1"].Health; got == BackendHealthy {
		t.Error("a backend whose manifest could not be fingerprinted reads as healthy")
	}
}

// ---------------------------------------------------------------------------
// live execution
// ---------------------------------------------------------------------------

// TestAnAuthorisedCallReachesTheUpstreamAndReturnsItsResult — P3's exit
// condition in test form.
func TestAnAuthorisedCallReachesTheUpstreamAndReturnsItsResult(t *testing.T) {
	up := &recordingUpstream{reply: func(method string) (any, *mcpwire.RPCError) {
		if method == mcpwire.MethodToolsCall {
			return mcpwire.CallToolResult{Content: []mcpwire.ContentBlock{{Type: "text", Text: "42 rows"}}}, nil
		}
		return mcpwire.ListToolsResult{}, nil
	}}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	mux := newExecutingServer(t, srv.URL, false)
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":{"sql":"select 1"}}}`, nil)
	if env.Error != nil {
		t.Fatalf("the call was refused: %+v", env.Error)
	}
	var res mcpwire.CallToolResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Content) != 1 || res.Content[0].Text != "42 rows" {
		t.Errorf("the upstream result did not come back: %+v", res)
	}
	// 🔴 The upstream was asked for the tool's OWN name, not our alias.
	if got := up.calledMethods(); len(got) == 0 || got[len(got)-1] != mcpwire.MethodToolsCall {
		t.Errorf("tools/call did not reach the upstream: %v", got)
	}
}

// TestAnAliasIsResolvedToTheUpstreamName — the backend has never heard of our
// renaming.
func TestAnAliasIsResolvedToTheUpstreamName(t *testing.T) {
	var sawName string
	up := &recordingUpstream{reply: func(method string) (any, *mcpwire.RPCError) {
		return mcpwire.CallToolResult{}, nil
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env mcpwire.Envelope
		_ = json.Unmarshal(body, &env)
		var call mcpwire.CallToolRequest
		_ = json.Unmarshal(env.Params, &call)
		sawName = call.Name
		w.Header().Set("Content-Type", "application/json")
		payload, _ := json.Marshal(mcpwire.Envelope{
			JSONRPC: mcpwire.JSONRPCVersion, ID: env.ID,
			Result: json.RawMessage(`{"content":[]}`),
		})
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	_ = up

	mux := newExecutingServer(t, srv.URL, true) // alias "sql_query"
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sql_query","arguments":{}}}`, nil)
	if env.Error != nil {
		t.Fatalf("the aliased call was refused: %+v", env.Error)
	}
	if sawName != "query_readonly" {
		t.Errorf("the upstream was asked for %q; it has never heard of our alias", sawName)
	}
}

// TestAnUnreachableUpstreamIsBlamedOnTheUpstream — and the reply does not leak
// the dial error, which can carry internal hostnames.
func TestAnUnreachableUpstreamIsBlamedOnTheUpstream(t *testing.T) {
	mux := newExecutingServer(t, "http://127.0.0.1:1/mcp", false)
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":{}}}`, nil)

	code := aikeyCode(t, env)
	if !strings.HasPrefix(code, "EXT_") {
		t.Errorf("aikey_code = %q; an upstream failure must carry the EXT_ prefix so the customer "+
			"knows who to contact", code)
	}
	if strings.Contains(env.Error.Message, "127.0.0.1") {
		t.Errorf("the reply leaked the upstream address: %q", env.Error.Message)
	}
}

// newExecutingServer builds a plane whose policy points at a real upstream.
func newExecutingServer(t *testing.T, endpoint string, withAlias bool) *http.ServeMux {
	t.Helper()
	tool := PolicyTool{
		ID: "t1", BackendID: "b1", Name: "query_readonly",
		Description: "Run a read-only SQL query.", InputSchema: `{"type":"object"}`,
		ManifestHash: "h1", State: ToolStatePublished,
	}
	if withAlias {
		tool.Alias = "sql_query"
	}
	store := NewPolicyStore()
	store.Store(&Policy{
		OrgID: testOrg, Version: 1,
		Backends: []PolicyBackend{{
			ID: "b1", Name: "github", Transport: TransportStreamableHTTP,
			EndpointURL: endpoint, Status: "active",
		}},
		Toolsets: []PolicyToolset{{
			ID: "ts1", Slug: testToolset, Status: "active", Tools: []PolicyTool{tool},
		}},
		Grants: []PolicyGrant{{SubjectKind: SubjectSeat, SubjectID: testSeat, VirtualServerID: "ts1"}},
	})
	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
		Logger:          discardLogger(),
		PolicyStore:     store,
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

type capturingReporter struct {
	mu      sync.Mutex
	reports []ObservedManifest
}

func (c *capturingReporter) Report(_ context.Context, _ string, m ObservedManifest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reports = append(c.reports, m)
	return nil
}

type failingReporter struct{}

func (failingReporter) Report(context.Context, string, ObservedManifest) error {
	return io.ErrUnexpectedEOF
}

func asUpstream(err error, target **UpstreamError) bool {
	for err != nil {
		if ue, ok := err.(*UpstreamError); ok {
			*target = ue
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// TestTheSyncerIsReadLivelyNotCapturedAtWiringTime.
//
// 🔴 The manifest sync starts AFTER the HTTP surface is built (it probes the
// backends the policy names, so it has nothing to do until the policy rail has
// run). A handler that captured the syncer VALUE at construction would pin nil
// forever — and the failure is silent: every circuit cooldown reads as zero, so
// MCP_BACKEND_UNAVAILABLE loses its retry hint and a model retries a dead
// backend immediately and forever.
func TestTheSyncerIsReadLivelyNotCapturedAtWiringTime(t *testing.T) {
	var installed *ManifestSyncer // nil at construction, exactly like startup

	h := NewHandler(Config{
		Catalog:         &StaticCatalog{Toolsets: map[string]ToolsetView{}},
		Resolver:        stubResolver{},
		Isolation:       NewIsolation(4, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
		Logger:          discardLogger(),
		Syncer:          func() *ManifestSyncer { return installed },
	})
	if h.currentSyncer() != nil {
		t.Fatal("precondition: no syncer should be installed yet")
	}

	// The sync starts later, as it does in app wiring.
	installed = NewManifestSyncer(testOrg, NewPolicyStore(), nil, nil, nil, discardLogger())

	if h.currentSyncer() == nil {
		t.Fatal("the handler captured the syncer at construction; it would report a zero cooldown forever")
	}
}
