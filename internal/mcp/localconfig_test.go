package mcp

// P5 — Personal edition's local config.
//
// The property under test throughout: 🔴 Personal gets less CONFIGURATION,
// never fewer CHECKS. Every assertion here is really asking "does the locally
// produced snapshot go through the same evaluator as a control-plane one".

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLocalConfig(t *testing.T, cfg string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, LocalConfigFilename)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// loading
// ---------------------------------------------------------------------------

func TestLocalConfig_AbsentIsDistinctFromEmpty(t *testing.T) {
	// 🔴 The two must not collapse. Absent means "never configured" and the
	// truthful answer is no endpoint at all; empty means "removed the last
	// backend" and the client should see a toolset with zero tools rather than
	// a 404 it will read as a broken gateway.
	_, err := LoadLocalConfig(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, ErrNoLocalConfig) {
		t.Fatalf("a missing file must report ErrNoLocalConfig, got %v", err)
	}

	cfg, err := LoadLocalConfig(writeLocalConfig(t, `{"backends":[]}`))
	if err != nil {
		t.Fatalf("an empty config is valid: %v", err)
	}
	if len(cfg.Backends) != 0 {
		t.Fatalf("want 0 backends, got %d", len(cfg.Backends))
	}
}

func TestLocalConfig_MalformedFileNamesItselfAndTheProblem(t *testing.T) {
	_, err := LoadLocalConfig(writeLocalConfig(t, `{"backends":[`))
	if err == nil {
		t.Fatal("truncated JSON must be an error")
	}
	// 🔴 The user edited this file, possibly by hand. A parse error without the
	// path is only actionable if you already know which file it came from.
	if !strings.Contains(err.Error(), LocalConfigFilename) {
		t.Fatalf("the error must name the file: %v", err)
	}
}

func TestLocalConfig_RejectsTheThreeThingsThatBreakLater(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"no name", `{"backends":[{"command":"x"}]}`, "no name"},
		{"no command", `{"backends":[{"name":"pg"}]}`, "no command"},
		{"duplicate names", `{"backends":[{"name":"pg","command":"a"},{"name":"pg","command":"b"}]}`, "both named"},
		{
			// 🔴 Caught at LOAD, not at spawn. At load it is one clear message
			// during startup; at spawn it is a tool that fails on first use,
			// which the user may not try for days.
			"credential without a variable name",
			`{"backends":[{"name":"pg","command":"a","credential_alias":"db"}]}`,
			"credential_env",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadLocalConfig(writeLocalConfig(t, tc.body))
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the message must point at the fix (%q): %v", tc.want, err)
			}
		})
	}
}

// TestLocalConfig_HasNowhereToPutASecret is a STRUCTURAL fence.
//
// 🔴 The whole product claim is "no plaintext credential in the developer's
// config file". A future `env` map on LocalBackend would reintroduce exactly
// the thing being replaced — and it would look like a convenience, because it
// is one. The type having nowhere to put a secret is worth more than a comment
// asking people not to.
func TestLocalConfig_HasNowhereToPutASecret(t *testing.T) {
	blob, err := json.Marshal(LocalBackend{
		Name: "pg", Command: "npx", CredentialAlias: "db", CredentialEnv: "PGPASSWORD",
	})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(blob, &fields); err != nil {
		t.Fatal(err)
	}
	// An allowlist, so a NEW field has to be considered rather than absorbed.
	allowed := map[string]bool{
		"name": true, "command": true, "args": true,
		"credential_alias": true, "credential_env": true, "disabled": true,
	}
	for k := range fields {
		if !allowed[k] {
			t.Errorf("LocalBackend grew a field %q. If it can hold a secret, it must not exist: "+
				"credentials belong in the vault and are referenced by alias. If it genuinely "+
				"cannot, add it to this allowlist deliberately.", k)
		}
	}
	// And the alias field must not be usable AS a secret by accident.
	if strings.Contains(string(blob), "PGPASSWORD=") {
		t.Fatal("the serialised backend looks like it carries a value, not a variable name")
	}
}

// ---------------------------------------------------------------------------
// translation
// ---------------------------------------------------------------------------

func okLookup(secret string) SecretLookup {
	return func(alias string) (string, error) { return secret, nil }
}

// TestBuildLocalPolicy_ProducesTheSameShapeTheControlPlaneDoes is the fence for
// the core design decision: one snapshot model, two producers.
func TestBuildLocalPolicy_ProducesTheSameShapeTheControlPlaneDoes(t *testing.T) {
	cfg, err := LoadLocalConfig(writeLocalConfig(t, `{"backends":[
		{"name":"postgres","command":"npx","args":["-y","@x/server-postgres"],
		 "credential_alias":"db-readonly","credential_env":"PGPASSWORD"}]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	policy, problems := BuildLocalPolicy(cfg, "", "", okLookup("s3cret"))
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(policy.Backends) != 1 {
		t.Fatalf("want 1 backend, got %d", len(policy.Backends))
	}
	b := policy.Backends[0]
	if b.Transport != TransportStdio || b.Command != "npx" || b.Status != StatusActive {
		t.Fatalf("backend not translated: %+v", b)
	}
	// 🔴 Tools are EMPTY. The user's file says which servers to host, never
	// which tools they have — a file that could declare tools could declare
	// write_op:false for one that writes.
	if len(policy.Toolsets) != 1 || len(policy.Toolsets[0].Tools) != 0 {
		t.Fatalf("the local policy must declare no tools; discovery is the syncer's job: %+v", policy.Toolsets)
	}
	if policy.Toolsets[0].Slug != LocalToolsetSlug {
		t.Fatalf("the local slug is a public contract: %q", policy.Toolsets[0].Slug)
	}
	// The grant is a real row, not a bypass.
	if len(policy.Grants) != 1 || policy.Grants[0].SubjectKind != SubjectSeat {
		t.Fatalf("Personal must carry an explicit grant row so the SAME evaluator admits the "+
			"call; got %+v", policy.Grants)
	}
}

// TestBuildLocalPolicy_TheGrantIsEvaluatedByTheRealCatalog — the assertion that
// makes the one above worth anything.
//
// 🔴 It drives the REAL PolicyCatalog, the same type Production uses. A local
// policy that merely looked right but did not satisfy the actual evaluator
// would produce a Personal install where every tool call 404s.
func TestBuildLocalPolicy_TheGrantIsEvaluatedByTheRealCatalog(t *testing.T) {
	cfg, err := LoadLocalConfig(writeLocalConfig(t,
		`{"backends":[{"name":"postgres","command":"npx"}]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	policy, _ := BuildLocalPolicy(cfg, "", "", nil)
	// Give the toolset a tool, as the manifest syncer would after discovery.
	policy.Toolsets[0].Tools = []PolicyTool{{
		ID: "t1", BackendID: "postgres", Name: "query", State: ToolStatePublished,
		InputSchema: `{"type":"object"}`,
	}}

	store := NewPolicyStore()
	store.Store(policy)
	cat := NewPolicyCatalog(store, nil)

	view, found := cat.Toolset(context.Background(), "", "", LocalToolsetSlug)
	if !found {
		t.Fatal("🔴 the real catalog does not admit the locally-built policy; on Personal every " +
			"tools/list would 404 with no way to tell why")
	}
	if len(view.Tools) != 1 || view.Tools[0].Name != "query" {
		t.Fatalf("catalog view: %+v", view.Tools)
	}
	// And a DIFFERENT seat must not be admitted by it — the grant is real, so it
	// discriminates.
	if _, found := cat.Toolset(context.Background(), "", "somebody-else", LocalToolsetSlug); found {
		t.Fatal("🔴 the local grant admitted a seat it does not name; the grant row is being " +
			"ignored, which means the evaluator is not actually running")
	}
}

// TestBuildLocalPolicy_AMissingCredentialDisablesTheBackendLoudly.
//
// 🔴 Disabled and REPORTED, not dropped. A silently-dropped backend is
// indistinguishable from one the user never configured — so they re-run
// `aikey mcp add`, it succeeds, and nothing changes.
func TestBuildLocalPolicy_AMissingCredentialDisablesTheBackendLoudly(t *testing.T) {
	cfg, err := LoadLocalConfig(writeLocalConfig(t, `{"backends":[
		{"name":"pg","command":"npx","credential_alias":"absent","credential_env":"PGPASSWORD"}]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	missing := SecretLookup(func(string) (string, error) { return "", errors.New("not in vault") })
	policy, problems := BuildLocalPolicy(cfg, "", "", missing)

	if len(policy.Backends) != 1 {
		t.Fatalf("the backend must still be PUBLISHED (disabled), not dropped: %+v", policy.Backends)
	}
	if policy.Backends[0].Status != StatusDisabled {
		t.Fatalf("a backend whose credential cannot be read must be disabled, got %q",
			policy.Backends[0].Status)
	}
	if len(problems) != 1 {
		t.Fatalf("want exactly one reported problem, got %v", problems)
	}
	// The message must say what to run.
	if !strings.Contains(problems[0].Error(), "aikey add") {
		t.Fatalf("the problem must name the fix: %v", problems[0])
	}
}

// ---------------------------------------------------------------------------
// credential material
// ---------------------------------------------------------------------------

// TestLocalCredentialMaterial_UsesTheSameShapeAsTheControlPlaneRail.
//
// 🔴 Same type, same store, same resolver, same never-in-argv injection. A
// separate "local credential" path would be a second home for the redaction and
// env-injection rules, and the second implementation is the one that gets them
// wrong.
func TestLocalCredentialMaterial_UsesTheSameShapeAsTheControlPlaneRail(t *testing.T) {
	const secret = "local_PLAINTEXT_ONLY_IN_ENV_8823"
	cfg, err := LoadLocalConfig(writeLocalConfig(t, `{"backends":[
		{"name":"pg","command":"npx","credential_alias":"db","credential_env":"PGPASSWORD"}]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	material, problems := LocalCredentialMaterial(cfg, okLookup(secret))
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	if len(material) != 1 {
		t.Fatalf("want 1 material, got %d", len(material))
	}
	m := material[0]
	if m.ID != "db" || m.Kind != CredentialKindEnv || m.HeaderName != "PGPASSWORD" || m.Secret != secret {
		t.Fatalf("material: %+v", m)
	}

	// It must flow through the SAME store the control-plane rail feeds, and the
	// resolver must produce a credential the stdio transport can inject.
	store := NewCredentialStore("", nil, nil) // memory-only: no vault in this test
	store.Replace(context.Background(), material)
	got, err := store.Resolve(context.Background(), "", "db")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Kind != CredentialKindEnv || got.Secret != secret {
		t.Fatalf("resolved credential: %+v", got)
	}
	// And it still cannot be printed or serialised.
	if s := fmt.Sprintf("%v %s %+v", got, got, got); strings.Contains(s, secret) {
		t.Fatalf("🔴 the local credential printed its secret: %s", s)
	}
}

// TestLocalCredentialMaterial_SkipsDisabledBackends — a backend the user turned
// off must not have its secret decrypted and held in memory.
func TestLocalCredentialMaterial_SkipsDisabledBackends(t *testing.T) {
	cfg, err := LoadLocalConfig(writeLocalConfig(t, `{"backends":[
		{"name":"pg","command":"npx","credential_alias":"db","credential_env":"PGPASSWORD","disabled":true}]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	material, _ := LocalCredentialMaterial(cfg, okLookup("s"))
	if len(material) != 0 {
		t.Fatalf("a disabled backend's credential must not be resolved into memory: %+v", material)
	}
}
