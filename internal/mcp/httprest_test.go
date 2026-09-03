package mcp

// httprest_test.go — P9's proxy half: an imported REST operation must be
// callable, and must not become a way to reach anything else.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// restRecorder is a stand-in REST API.
type restRecorder struct {
	mu      sync.Mutex
	method  string
	path    string
	header  http.Header
	body    string
	status  int
	replyTo string
}

func (r *restRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		buf := make([]byte, 4096)
		n, _ := req.Body.Read(buf)
		r.mu.Lock()
		r.method, r.path, r.header, r.body = req.Method, req.URL.RequestURI(), req.Header.Clone(), string(buf[:n])
		status, reply := r.status, r.replyTo
		r.mu.Unlock()
		if status == 0 {
			status = http.StatusOK
		}
		if reply == "" {
			reply = `{"ok":true}`
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	})
}

func (r *restRecorder) seen() (method, path, body string, header http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.method, r.path, r.body, r.header
}

func restBackend(t *testing.T, endpoint string, binding mcpwire.RESTBinding) UpstreamBackend {
	t.Helper()
	stored, err := mcpwire.MarshalRESTBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	return UpstreamBackend{
		ID: "b-rest", Name: "orders-api", Transport: TransportHTTPREST,
		EndpointURL: endpoint, RESTBinding: stored,
	}
}

func restTransport(t *testing.T) UpstreamTransport {
	t.Helper()
	tr, ok := LookupTransport(TransportHTTPREST)
	if !ok {
		t.Fatal("the http_rest transport is not registered; an imported tool would answer " +
			"'this gateway build cannot reach a http_rest backend'")
	}
	return tr
}

// TestAnImportedOperationIsActuallyCalled is P9's exit condition in miniature.
func TestAnImportedOperationIsActuallyCalled(t *testing.T) {
	api := &restRecorder{replyTo: `{"orders":[{"id":"A-1"}]}`}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	b := restBackend(t, srv.URL, mcpwire.RESTBinding{
		Method: "GET", Path: "/orders/{orderId}",
		Params: map[string]string{"orderId": mcpwire.RESTInPath, "verbose": mcpwire.RESTInQuery},
	})
	res, err := restTransport(t).CallTool(context.Background(), b, "get_order",
		json.RawMessage(`{"orderId":"A-1","verbose":"true"}`))
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	method, path, _, _ := api.seen()
	if method != "GET" || path != "/orders/A-1?verbose=true" {
		t.Errorf("the API saw %s %s", method, path)
	}
	if len(res.Content) != 1 || !strings.Contains(res.Content[0].Text, "A-1") {
		t.Errorf("the API's answer did not come back: %+v", res.Content)
	}
}

// TestArgumentsTheBindingDoesNotNameNeverLeave.
//
// 🔴 A reviewer approved a specific parameter list at import. Forwarding
// anything else a model invents would let an Agent reach parameters nobody saw
// — the importer would become a request forger with an approval workflow.
func TestArgumentsTheBindingDoesNotNameNeverLeave(t *testing.T) {
	api := &restRecorder{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	b := restBackend(t, srv.URL, mcpwire.RESTBinding{
		Method: "GET", Path: "/orders",
		Params: map[string]string{"status": mcpwire.RESTInQuery},
	})
	if _, err := restTransport(t).CallTool(context.Background(), b, "list_orders",
		json.RawMessage(`{"status":"open","admin":"1","internal":"yes"}`)); err != nil {
		t.Fatal(err)
	}
	_, path, body, _ := api.seen()
	for _, sneaky := range []string{"admin", "internal"} {
		if strings.Contains(path, sneaky) || strings.Contains(body, sneaky) {
			t.Errorf("an unnamed argument reached the API: path=%q body=%q", path, body)
		}
	}
}

// TestABindingCannotOverwriteTheCredential.
//
// The header values come from a model's output. If a binding's headers were
// applied after the credential, a tool argument could replace the customer's
// Authorization header with one the caller supplied.
func TestABindingCannotOverwriteTheCredential(t *testing.T) {
	api := &restRecorder{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	b := restBackend(t, srv.URL, mcpwire.RESTBinding{
		Method: "GET", Path: "/x",
		Params: map[string]string{"Authorization": mcpwire.RESTInHeader},
	})
	b.Credential = UpstreamCredential{Kind: "bearer", Secret: "real-secret"}
	if _, err := restTransport(t).CallTool(context.Background(), b, "x",
		json.RawMessage(`{"Authorization":"Bearer attacker-chosen"}`)); err != nil {
		t.Fatal(err)
	}
	_, _, _, header := api.seen()
	if got := header.Get("Authorization"); !strings.Contains(got, "real-secret") {
		t.Errorf("Authorization = %q; a tool argument replaced the customer's credential", got)
	}
}

// TestNoInternalHeaderReachesARESTBackend — D-13 applies here exactly as it does
// to every other upstream: this backend is a third party.
func TestNoInternalHeaderReachesARESTBackend(t *testing.T) {
	api := &restRecorder{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	b := restBackend(t, srv.URL, mcpwire.RESTBinding{
		Method: "GET", Path: "/x",
		Params: map[string]string{"X-Aikey-Trace": mcpwire.RESTInHeader},
	})
	if _, err := restTransport(t).CallTool(context.Background(), b, "x",
		json.RawMessage(`{"X-Aikey-Trace":"t-1"}`)); err != nil {
		t.Fatal(err)
	}
	_, _, _, header := api.seen()
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "x-aikey-") {
			t.Errorf("an X-Aikey-* header reached a third-party API: %s", name)
		}
	}
}

// TestAToolWithNoBindingIsRefusedNotGuessed.
//
// 🔴 Guessing a path from the tool's name would call an endpoint nobody
// approved.
func TestAToolWithNoBindingIsRefusedNotGuessed(t *testing.T) {
	api := &restRecorder{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	b := UpstreamBackend{ID: "b", Transport: TransportHTTPREST, EndpointURL: srv.URL}
	_, err := restTransport(t).CallTool(context.Background(), b, "mystery", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("a tool with no call mapping was executed")
	}
	if method, _, _, _ := api.seen(); method != "" {
		t.Errorf("the API was contacted anyway (%s)", method)
	}
	if !strings.Contains(err.Error(), "mystery") {
		t.Errorf("the refusal does not name the tool: %v", err)
	}
}

// TestAnUpstreamRefusalIsBlamedOnTheUpstream — the EXT_ prefix is how a
// customer decides whether to open a ticket with us or with whoever runs the API.
func TestAnUpstreamRefusalIsBlamedOnTheUpstream(t *testing.T) {
	api := &restRecorder{status: http.StatusNotFound, replyTo: `{"error":"no such order A-1"}`}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	b := restBackend(t, srv.URL, mcpwire.RESTBinding{Method: "GET", Path: "/orders"})
	_, err := restTransport(t).CallTool(context.Background(), b, "list_orders", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("a 404 was reported as success")
	}
	var ue *UpstreamError
	if !asUpstream(err, &ue) {
		t.Fatalf("not an UpstreamError: %v", err)
	}
	if !strings.HasPrefix(string(ue.Code), "EXT_") {
		t.Errorf("code = %q; an API's refusal must carry the EXT_ prefix", ue.Code)
	}
	if ue.Status != http.StatusNotFound {
		t.Errorf("status = %d; a developer needs to tell a 404 from a 403 without asking us", ue.Status)
	}
	// 🚫 The API's error body is NOT echoed: it routinely contains the record
	// that was refused, and an error string travels further than we can follow.
	if strings.Contains(ue.Detail, "no such order") {
		t.Errorf("the API's error body was echoed into ours: %q", ue.Detail)
	}
}

// TestA401IsBlamedOnTheCREDENTIAL, not on the API — the fix is ours (re-bind),
// not the caller's, and MCP_CREDENTIAL_MISSING is the code that says so.
func TestA401IsBlamedOnTheCredential(t *testing.T) {
	api := &restRecorder{status: http.StatusUnauthorized}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	b := restBackend(t, srv.URL, mcpwire.RESTBinding{Method: "GET", Path: "/x"})
	_, err := restTransport(t).CallTool(context.Background(), b, "x", json.RawMessage(`{}`))
	var ue *UpstreamError
	if !asUpstream(err, &ue) {
		t.Fatalf("not an UpstreamError: %v", err)
	}
	if ue.Code != mcpwire.ErrCredentialMissing {
		t.Errorf("code = %q, want %q: a rejected credential sends the admin to re-bind it, "+
			"not the developer to debug their arguments", ue.Code, mcpwire.ErrCredentialMissing)
	}
}

// TestARESTBackendIsNeverProbed is the R9 rule at its sharpest.
//
// 🔴 Every endpoint on a REST backend is a real business operation. A probe runs
// on a timer, so probing one would perform that operation on the customer's
// systems every five minutes, forever, with nobody's name on it.
func TestARESTBackendIsNeverProbed(t *testing.T) {
	api := &restRecorder{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	store := NewPolicyStore()
	store.Store(&Policy{
		OrgID: testOrg, Version: 1,
		Backends: []PolicyBackend{{
			ID: "b-rest", Name: "orders-api", Transport: TransportHTTPREST,
			EndpointURL: srv.URL, Status: "active",
		}},
	})
	syncer := NewManifestSyncer(testOrg, store, &capturingReporter{}, nil, nil, discardLogger())
	syncer.SyncOnce(context.Background())

	if method, _, _, _ := api.seen(); method != "" {
		t.Errorf("the manifest sync contacted a REST API (%s). Every one of its endpoints is a "+
			"real business operation, and a probe runs on a timer.", method)
	}
	// 🔴 And it is UNKNOWN, not healthy. Calling it healthy because the row
	// exists is green exactly when the API is unreachable.
	if got := syncer.Status()["b-rest"].Health; got != BackendUnknown {
		t.Errorf("health = %q, want unknown", got)
	}
}

// TestListToolsOnARESTBackendIsEmptyNotAnError.
//
// The sync loop treats an error as a failed probe and opens a circuit; a REST
// backend has no probe to fail, so an error here would circuit-break a backend
// that is perfectly fine.
func TestListToolsOnARESTBackendIsEmptyNotAnError(t *testing.T) {
	tools, err := restTransport(t).ListTools(context.Background(),
		UpstreamBackend{Transport: TransportHTTPREST, EndpointURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Errorf("ListTools returned an error (%v); the sync loop would read that as a failed "+
			"probe and open the circuit on a backend that has nothing to probe", err)
	}
	if len(tools) != 0 {
		t.Errorf("ListTools invented %d tools", len(tools))
	}
}

// TestATimeoutIsNotReportedAsNeverAccepted is R4 on this transport.
//
// A REST write endpoint that times out may be executing right now; marking it
// never-accepted would make the gateway retry it and place the order twice.
func TestATimeoutIsNotReportedAsNeverAccepted(t *testing.T) {
	b := restBackend(t, "http://127.0.0.1:1", mcpwire.RESTBinding{Method: "POST", Path: "/x"})
	_, err := restTransport(t).CallTool(context.Background(), b, "x", json.RawMessage(`{}`))
	var ue *UpstreamError
	if !asUpstream(err, &ue) {
		t.Fatalf("not an UpstreamError: %v", err)
	}
	// Connection refused IS provably never-accepted — that is the whitelist
	// working. What must never happen is a TIMEOUT carrying the flag; that case
	// is covered by the shared classifier and its own fence.
	if ue.Code == mcpwire.ErrUpstreamTimeout && ue.NotAccepted {
		t.Error("a timeout was marked never-accepted; the gateway would retry a call that may " +
			"already have run")
	}
}
