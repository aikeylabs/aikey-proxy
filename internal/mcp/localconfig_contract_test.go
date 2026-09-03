package mcp

// The cross-language contract for ~/.aikey/mcp.json.
//
// 🔴 This file and `aikey-cli/src/commands_mcp.rs`'s
// `config_shape_matches_the_proxy_contract` assert against the SAME literal
// document, deliberately duplicated in both languages. There is no shared
// schema between a Rust CLI and a Go proxy, so the contract is kept by two
// tests that fail loudly the moment either side moves.
//
// The failure this prevents is the quiet one: the CLI reports "backend added",
// the proxy reports nothing wrong, and the developer's Agent simply has no
// tools — because one side spelled a field differently.
//
// 🔴 If you change this literal, change the Rust one in the same commit.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// contractDocument is exactly what `aikey mcp add` writes today, produced by
// running the real CLI. Kept verbatim, including the field ORDER and the
// omission of empty fields.
const contractDocument = `{
  "backends": [
    {
      "name": "postgres",
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-postgres"
      ],
      "credential_alias": "db-readonly",
      "credential_env": "PGPASSWORD"
    },
    {
      "name": "github",
      "command": "gh-mcp"
    },
    {
      "name": "off",
      "command": "foo",
      "credential_alias": "c",
      "credential_env": "X",
      "disabled": true
    }
  ]
}`

func TestCLIWrittenConfigIsReadableByThisProxy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, LocalConfigFilename)
	if err := os.WriteFile(path, []byte(contractDocument), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := LoadLocalConfig(path)
	if err != nil {
		t.Fatalf("the proxy cannot read what the CLI writes: %v", err)
	}
	if len(cfg.Backends) != 3 {
		t.Fatalf("want 3 backends, got %d", len(cfg.Backends))
	}

	pg := cfg.Backends[0]
	if pg.Name != "postgres" || pg.Command != "npx" {
		t.Fatalf("backend identity lost: %+v", pg)
	}
	// 🔴 Args order matters: `npx -y <pkg>` is not the same command as
	// `npx <pkg> -y`.
	if !reflect.DeepEqual(pg.Args, []string{"-y", "@modelcontextprotocol/server-postgres"}) {
		t.Fatalf("args lost or reordered in transit: %+v", pg.Args)
	}
	if pg.CredentialAlias != "db-readonly" || pg.CredentialEnv != "PGPASSWORD" {
		t.Fatalf("the credential REFERENCE is what makes this feature work; it was lost: %+v", pg)
	}
	// A backend with no credential must not acquire one.
	if cfg.Backends[1].CredentialAlias != "" || cfg.Backends[1].CredentialEnv != "" {
		t.Fatalf("a credential-less backend gained a credential: %+v", cfg.Backends[1])
	}
	if !cfg.Backends[2].Disabled {
		t.Fatalf("the disabled flag was lost, so a switched-off backend would be hosted: %+v", cfg.Backends[2])
	}

	// And it must survive translation into the policy the plane actually serves.
	policy, problems := BuildLocalPolicy(cfg, "", "", nil)
	if len(policy.Backends) != 3 {
		t.Fatalf("policy carries %d backends, want 3 (problems: %v)", len(policy.Backends), problems)
	}
	if policy.Backends[2].Status != StatusDisabled {
		t.Fatalf("the disabled backend is not disabled in the policy: %+v", policy.Backends[2])
	}
}

// TestLocalConfigPathSitsBesideTheVault pins WHERE the file is.
//
// 🔴 This was missing until the 5.6 drill pointed it out: every other test
// passed an explicit path, so moving the directory this function returns broke
// nothing. That is the most dangerous drift in the whole feature — the CLI
// writes to ~/.aikey/mcp.json, the proxy reads somewhere else, and BOTH report
// success while the developer's Agent has no tools.
//
// The CLI's counterpart is `config_path_matches_the_proxy`.
func TestLocalConfigPathSitsBesideTheVault(t *testing.T) {
	t.Setenv("AIKEY_MCP_CONFIG", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory on this host: %v", err)
	}
	got, err := LocalConfigPath()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := filepath.Join(home, ".aikey", LocalConfigFilename)
	if got != want {
		t.Fatalf("the config path moved.\n  got:  %s\n  want: %s\n"+
			"🔴 It must sit in ~/.aikey beside vault.db, and identically to the CLI's "+
			"resolve_aikey_dir().join(%q) \u2014 this file references credentials by vault "+
			"alias, so writing it where the proxy does not look produces a gateway that hosts "+
			"nothing while both sides report success.", got, want, "mcp.json")
	}
}

// TestLocalConfigPathOverrideIsSpelledTheSameAsTheCLIs — one override name,
// two languages. A CLI honouring a different variable would relocate its config
// while the proxy kept reading the real one; the two would never meet.
func TestLocalConfigPathOverrideIsSpelledTheSameAsTheCLIs(t *testing.T) {
	t.Setenv("AIKEY_MCP_CONFIG", "/tmp/somewhere/else.json")
	got, err := LocalConfigPath()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "/tmp/somewhere/else.json" {
		t.Fatalf("AIKEY_MCP_CONFIG is the ONLY override either side honours; got %q", got)
	}
}

// TestLocalBackendFieldSetIsTheContract pins the Go side's field names.
//
// 🔴 An allowlist, so a NEW field has to be added here deliberately — which is
// the moment to remember that the Rust writer needs it too. A field only Go
// knows about is silently absent from every config the CLI writes; a field only
// Rust knows about is silently ignored here. Both read as "the setting does
// nothing".
func TestLocalBackendFieldSetIsTheContract(t *testing.T) {
	blob, err := json.Marshal(LocalBackend{
		Name: "n", Command: "c", Args: []string{"a"},
		CredentialAlias: "al", CredentialEnv: "EV", Disabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(blob, &fields); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(fields))
	for k := range fields {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"args", "command", "credential_alias", "credential_env", "disabled", "name"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the mcp.json field set changed.\n  got:  %v\n  want: %v\n"+
			"🔴 If this is intentional, update aikey-cli/src/commands_mcp.rs "+
			"(McpBackend + config_shape_matches_the_proxy_contract) IN THE SAME CHANGE — "+
			"otherwise one side writes a field the other ignores and the setting silently "+
			"does nothing.", got, want)
	}
}
