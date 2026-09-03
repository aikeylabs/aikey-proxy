//go:build !windows

package mcp

// The Personal chain, over HTTP, end to end — P14 task 14.0.
//
// 🔴 This exists because the previous Personal end-to-end case
// (TestPersonalChain_FromCLIWrittenConfigToARealToolResult) goes
// `config → policy → transport.ListTools` and stops there. It was green for the
// entire time `/mcp/local` served `{"tools": []}` to every MCP client on every
// Personal install, because the catalog — the hop an actual client goes
// through — was never in the picture.
//
// So this one starts at the file `aikey mcp add` writes and finishes at a
// JSON-RPC `tools/call` over the real mux, through the real authentication, the
// real grant evaluation and the real freeze rule. What it still does NOT prove
// is that Claude Code specifically connects; that needs the client, and it is
// recorded as open rather than implied.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

func TestPersonalOverHTTP_AClientListsAndCallsTheToolsItHosts(t *testing.T) {
	const secret = "http_chain_PGPASSWORD_2731"

	// 1. The document the CLI writes.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, LocalConfigFilename)
	bin := fakeMCPBinary(t)
	doc := `{"backends":[{"name":"localpg","command":"` + bin + `",` +
		`"credential_alias":"db-readonly","credential_env":"PGPASSWORD"}]}`
	if err := os.WriteFile(cfgPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKEMCP_SECRET_ENV", "PGPASSWORD")

	// 2. The proxy's boot path: load, translate, store.
	cfg, err := LoadLocalConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	lookup := SecretLookup(func(alias string) (string, error) { return secret, nil })
	policy, problems := BuildLocalPolicy(cfg, "", "", lookup)
	if len(problems) != 0 {
		t.Fatalf("translation problems: %v", problems)
	}
	store := NewPolicyStore()
	store.Store(policy)

	credStore := NewCredentialStore("", nil, nil)
	material, credProblems := LocalCredentialMaterial(cfg, lookup)
	if len(credProblems) != 0 {
		t.Fatalf("credential problems: %v", credProblems)
	}
	credStore.Replace(context.Background(), material)

	// 3. The probe round that fills the toolset. 🔴 The hop that did not exist.
	pub := NewLocalPublisher(filepath.Join(dir, LocalManifestFilename), store, discardLogger())
	syncer := NewManifestSyncer("", store, nil, pub, credStore, discardLogger())
	syncer.SyncOnce(context.Background())

	// 🔴 The first-review gate (task 14.3). Before this, the backend's tools are
	// recorded and NOT served — which is asserted first, because "the gate is
	// closed" and "the producer is broken" look identical from the client side
	// and this test exists to tell them apart.
	if v, _ := NewPolicyCatalog(store, nil).Toolset(context.Background(), "", "", LocalToolsetSlug); len(v.Tools) != 0 {
		t.Fatalf("a backend nobody has reviewed is already serving %d tool(s)", len(v.Tools))
	}
	if _, err := pub.Accept("localpg", nil); err != nil {
		t.Fatalf("first review: %v", err)
	}

	// 4. The real plane, mounted the way app.go mounts it.
	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: "", SeatID: ""}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		Credentials:     credStore,
		PolicyStore:     store,
		LocalApprovals:  pub,
		Syncer:          func() *ManifestSyncer { return syncer },
		ExternalBaseURL: "http://127.0.0.1:8787",
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// 5. What a client actually does.
	_, env := rpc(t, mux, "/mcp/"+LocalToolsetSlug, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	if env.Error != nil {
		t.Fatalf("tools/list: %+v", env.Error)
	}
	var list mcpwire.ListToolsResult
	if err := json.Unmarshal(env.Result, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) == 0 {
		t.Fatal("🔴 an MCP client connecting to /mcp/local saw ZERO tools. This is the " +
			"defect task 14.0 records, and it is what `aikey mcp adopt` would have left " +
			"every developer with: their client repointed at a gateway that offers nothing.")
	}

	// 6. ...and calling one reaches the child WITH its credential — which is the
	// only assertion that distinguishes "wired" from "wired and delivering".
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` +
		list.Tools[0].Name + `","arguments":{}}}`
	_, env = rpc(t, mux, "/mcp/"+LocalToolsetSlug, testToken, call, nil)
	if env.Error != nil {
		t.Fatalf("tools/call: %+v", env.Error)
	}
	var res mcpwire.CallToolResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Content) == 0 || res.Content[0].Text != "secret_from_env="+secret {
		t.Fatalf("the credential did not travel config → alias → policy → store → child env; "+
			"the child reported %+v", res.Content)
	}

	// 7. And /health/mcp — the endpoint a release gate reads — agrees.
	rec := readHealth(t, mux)
	if rec.Backends["localpg"] != string(BackendHealthy) {
		t.Fatalf("health reports localpg as %q", rec.Backends["localpg"])
	}
	if rec.ToolsAddedSinceSetup == nil || *rec.ToolsAddedSinceSetup != 0 {
		t.Fatalf("the first probe is the baseline, so nothing has been ADDED since setup: %+v",
			rec.ToolsAddedSinceSetup)
	}
	if rec.ToolApprovalsUnreadable != "" {
		t.Fatalf("approvals unreadable: %s", rec.ToolApprovalsUnreadable)
	}
}

func readHealth(t *testing.T, mux *http.ServeMux) HealthDocument {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/mcp", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/health/mcp returned %d", rec.Code)
	}
	var doc HealthDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}
