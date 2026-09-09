//go:build !windows

package mcp

// The whole Personal chain, in one test: the document the CLI writes → the
// loader → the policy → the credential store → a real child process → a tool
// result whose content proves the credential arrived.
//
// 🔴 Self-contained on purpose. The first version of this took the config path
// and the binary from environment variables and t.Skip()ed without them — which
// means it would have skipped in CI and reported success, the exact "silently
// skipped = never tested" trap the project rules call out. It now builds its
// own inputs, so it either runs or fails.
//
// What it does NOT prove: that a real MCP client (Claude Code) connects to
// /mcp/local over HTTP. That needs the HTTP plane and a real client, and is
// still open — see the P5 close-out.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersonalChain_FromCLIWrittenConfigToARealToolResult(t *testing.T) {
	const secret = "chain_PGPASSWORD_value_5517"

	// 1. The document `aikey mcp add` produces, verbatim from the contract.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, LocalConfigFilename)
	bin := fakeMCPBinary(t)
	doc := `{
  "backends": [
    {
      "name": "localpg",
      "command": "` + bin + `",
      "credential_alias": "db-readonly",
      "credential_env": "PGPASSWORD"
    }
  ]
}`
	if err := os.WriteFile(cfgPath, []byte(doc), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// The child reports whichever variable it is told to look at.
	t.Setenv("FAKEMCP_SECRET_ENV", "PGPASSWORD")

	// 2. The proxy loads it.
	cfg, err := LoadLocalConfig(cfgPath)
	if err != nil {
		t.Fatalf("the proxy cannot read the CLI's config: %v", err)
	}

	// 3. The vault resolves the alias. (In production this is the real vault;
	// what matters here is that the POLICY carries an alias and the STORE is
	// what turns it into material — nothing in between ever holds plaintext.)
	lookup := SecretLookup(func(alias string) (string, error) {
		if alias != "db-readonly" {
			t.Fatalf("the policy asked for alias %q, which the config never named", alias)
		}
		return secret, nil
	})

	policy, problems := BuildLocalPolicy(cfg, "", "", lookup)
	if len(problems) != 0 {
		t.Fatalf("translation problems: %v", problems)
	}
	if len(policy.Backends) != 1 || policy.Backends[0].Status != StatusActive {
		t.Fatalf("policy: %+v", policy.Backends)
	}

	material, credProblems := LocalCredentialMaterial(cfg, lookup)
	if len(credProblems) != 0 {
		t.Fatalf("credential problems: %v", credProblems)
	}
	store := NewCredentialStore("", nil, nil) // memory only; no vault key in a test
	store.Replace(context.Background(), material)

	// 4. The plane resolves and calls, exactly as a tools/call would.
	pb := policy.Backends[0]
	cred, err := store.Resolve(context.Background(), "", pb.CredentialID)
	if err != nil {
		t.Fatalf("resolve credential: %v", err)
	}
	up := UpstreamBackend{
		ID: pb.ID, Name: pb.Name, Transport: pb.Transport,
		Command: pb.Command, Args: pb.Args,
		CredentialID: pb.CredentialID, Credential: cred,
	}
	tr := NewStdioTransport(nil)
	t.Cleanup(func() { tr.Shutdown(context.Background()) })

	tools, err := tr.ListTools(context.Background(), up)
	if err != nil {
		t.Fatalf("tools/list through the CLI-written config: %v", err)
	}
	if len(tools) == 0 {
		t.Fatal("the hosted backend exposed no tools")
	}
	res, err := tr.CallTool(context.Background(), up, tools[0].Name, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}

	// 5. 🔴 The assertion that makes the whole chain meaningful: the child says
	// what it found in its ENVIRONMENT. Anything less — "the call succeeded" —
	// would pass against a build that never delivered the credential at all.
	if want := "secret_from_env=" + secret; res.Content[0].Text != want {
		t.Fatalf("the credential did not travel config → alias → policy → store → child env.\n"+
			"  child saw: %q\n  expected:  %q", res.Content[0].Text, want)
	}

	// ...and it is still nowhere it should not be.
	pid := childPID(t, tr, up.ID)
	if line := processCommandLine(t, pid); strings.Contains(line, secret) {
		t.Fatalf("🔴 the credential is in the hosted backend's argv: %s", line)
	}
}
