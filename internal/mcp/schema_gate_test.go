package mcp

// Fence 6.F5 — malformed arguments are refused WITH a field path, and the
// upstream sees ZERO calls.
//
// 🔴 The zero-calls half is the requirement, and it is the half a unit test of
// the validator alone cannot prove. This gateway sits in front of a customer's
// production database; "let the backend reject it" means a malformed call
// reaches that database first. So this drives the REAL handler over HTTP
// against a REAL upstream that counts what it receives.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// schemaGateStack wires the policy-backed catalog (the shipping one) to a real
// HTTP upstream, so an authorised call really would reach it.
func schemaGateStack(t *testing.T) (*http.ServeMux, *recordingUpstream) {
	t.Helper()
	up := &recordingUpstream{}
	srv := httptest.NewServer(up.handler())
	t.Cleanup(srv.Close)

	policy := &Policy{
		OrgID: testOrg, Version: 1,
		Backends: []PolicyBackend{{
			ID: "b1", Name: "db", Transport: TransportStreamableHTTP,
			EndpointURL: srv.URL, Status: StatusActive,
		}},
		Toolsets: []PolicyToolset{{
			ID: "ts1", Slug: testToolset, Title: "Dev Tools", Status: StatusActive,
			Tools: []PolicyTool{{
				ID: "t1", BackendID: "b1", Name: "query_readonly", State: ToolStatePublished,
				InputSchema: `{"type":"object","required":["sql"],
				               "properties":{"sql":{"type":"string","minLength":1},
				                             "limit":{"type":"integer","minimum":1,"maximum":100}}}`,
			}},
		}},
		Grants: []PolicyGrant{{SubjectKind: SubjectSeat, SubjectID: testSeat, VirtualServerID: "ts1"}},
	}
	store := NewPolicyStore()
	store.Store(policy)

	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
		PolicyStore:     store,
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, up
}

func TestFence_6F5_MalformedArgumentsNeverReachTheUpstream(t *testing.T) {
	for _, tc := range []struct{ name, args, wantPath string }{
		{"missing required", `{}`, "$.sql"},
		{"wrong type", `{"sql":42}`, "$.sql"},
		{"out of range", `{"sql":"select 1","limit":9999}`, "$.limit"},
		{"empty string", `{"sql":""}`, "$.sql"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, up := schemaGateStack(t)
			rec, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
				`{"jsonrpc":"2.0","id":1,"method":"tools/call",`+
					`"params":{"name":"query_readonly","arguments":`+tc.args+`}}`, nil)

			if env.Error == nil {
				t.Fatalf("malformed arguments must be refused; got %s", rec.Body)
			}
			var data errorData
			if err := json.Unmarshal(env.Error.Data, &data); err != nil {
				t.Fatalf("error data: %v (%s)", err, env.Error.Data)
			}
			if data.AiKeyCode != string(mcpwire.ErrSchemaInvalid) {
				t.Fatalf("want %s, got %s", mcpwire.ErrSchemaInvalid, data.AiKeyCode)
			}
			// 🔴 The path, because the consumer is a model: "arguments are
			// invalid" is not something it can act on.
			if data.FieldPath != tc.wantPath {
				t.Fatalf("field_path: want %s got %s", tc.wantPath, data.FieldPath)
			}
			if !strings.Contains(env.Error.Message, tc.wantPath) {
				t.Fatalf("the message must name the field too: %q", env.Error.Message)
			}
			// ...and it must say the call did not happen, or a developer cannot
			// tell whether their database already saw it.
			if !strings.Contains(env.Error.Message, "NOT called") {
				t.Fatalf("the message must state the upstream was not called: %q", env.Error.Message)
			}

			// 🔴 THE FENCE: zero upstream calls.
			up.mu.Lock()
			methods := append([]string(nil), up.methods...)
			up.mu.Unlock()
			if len(methods) != 0 {
				t.Fatalf("🔴 the upstream WAS contacted with malformed arguments (%v). On a real "+
					"deployment that is a customer's production database receiving a call the "+
					"gateway had already decided was invalid.", methods)
			}
		})
	}
}

// TestFence_6F5_ValidArgumentsDoReachTheUpstream is the control.
//
// 🔴 Without it, "zero upstream calls" passes against a build where NOTHING
// reaches the upstream — a gateway that refuses everything would score
// perfectly on the fence above.
func TestFence_6F5_ValidArgumentsDoReachTheUpstream(t *testing.T) {
	mux, up := schemaGateStack(t)
	up.reply = func(method string) (any, *mcpwire.RPCError) {
		if method == mcpwire.MethodToolsCall {
			return mcpwire.CallToolResult{Content: []mcpwire.ContentBlock{{Type: "text", Text: "1 row"}}}, nil
		}
		return mcpwire.ListToolsResult{}, nil
	}
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call",`+
			`"params":{"name":"query_readonly","arguments":{"sql":"select 1","limit":10}}}`, nil)
	if env.Error != nil {
		t.Fatalf("a VALID call was refused: %+v", env.Error)
	}
	up.mu.Lock()
	methods := append([]string(nil), up.methods...)
	up.mu.Unlock()
	if len(methods) == 0 {
		t.Fatal("the control case never reached the upstream, so the zero-calls fence above " +
			"proves nothing — it would pass against a gateway that refuses everything")
	}
}
