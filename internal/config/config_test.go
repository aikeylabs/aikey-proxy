package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TC-B6: AIKEY_PROXY_LOG_LEVEL env override takes effect after defaults
// have been applied, even without a user file. Stage C-3 of scheme §9
// step 10 — log level归 system per scheme v8 SR8, but operators need a
// way to bump verbosity without editing yaml.
func TestApplyEnvOverrides_LogLevel(t *testing.T) {
	t.Setenv("AIKEY_PROXY_LOG_LEVEL", "debug")
	cfg := &Config{}
	cfg.applyDefaults()
	cfg.applyEnvOverrides()
	if cfg.Log.Level != "debug" {
		t.Errorf("AIKEY_PROXY_LOG_LEVEL not honored: got %q, want debug", cfg.Log.Level)
	}
}

// Empty/unset env preserves the yaml/default value.
func TestApplyEnvOverrides_LogLevelUnsetKeepsDefault(t *testing.T) {
	t.Setenv("AIKEY_PROXY_LOG_LEVEL", "")
	cfg := &Config{}
	cfg.applyDefaults()
	cfg.applyEnvOverrides()
	if cfg.Log.Level != DefaultLogLevel {
		t.Errorf("empty env should preserve default %q, got %q", DefaultLogLevel, cfg.Log.Level)
	}
}

// Why: templates used to leave `wal_dir` commented which silently disabled
// the v5 canonical event log. This regression test ensures that when a
// rendered config omits `wal_dir`, the proxy still ends up with a sane
// default pointing at the same directory the CLI reader uses
// (aikey-cli/src/usage_wal.rs::default_wal_dir).
func TestExpandPaths_DefaultsWALDirWhenEmpty(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir available on this runner: %v", err)
	}

	c := &Config{}
	c.expandPaths()

	want := filepath.Join(home, ".aikey", "data", "usage-wal")
	if c.Events.WALDir != want {
		t.Fatalf("empty WALDir should default to %q, got %q", want, c.Events.WALDir)
	}
}

// An operator-supplied path must be honoured verbatim (after `~` expansion),
// so users who do care about placement don't get silently overridden.
func TestExpandPaths_PreservesExplicitWALDir(t *testing.T) {
	c := &Config{}
	c.Events.WALDir = "/var/log/aikey/usage-wal"
	c.expandPaths()

	if c.Events.WALDir != "/var/log/aikey/usage-wal" {
		t.Fatalf("explicit WALDir should be unchanged, got %q", c.Events.WALDir)
	}
}

// Tilde expansion still works for operator-supplied paths with `~/`.
func TestExpandPaths_ExpandsTildeInWALDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir available: %v", err)
	}

	c := &Config{}
	c.Events.WALDir = "~/custom/wal"
	c.expandPaths()

	if !strings.HasPrefix(c.Events.WALDir, home) {
		t.Fatalf("expected tilde expanded under home, got %q", c.Events.WALDir)
	}
	if !strings.HasSuffix(c.Events.WALDir, filepath.Join("custom", "wal")) {
		t.Fatalf("expected suffix custom/wal, got %q", c.Events.WALDir)
	}
}

// ── 2026-05-11 F1 fix: aikey-user.yaml proxy: section merge ───────────────
//
// Load() now reads aikey-user.yaml from the same directory and merges its
// `proxy:` subtree on top of the system yaml. These tests pin the merge
// behaviour we depend on so a future refactor that drops or weakens it
// won't silently re-introduce the "make restart-personal wipes team
// override" bug.

const systemProxyYaml = `
listen:
  host: "127.0.0.1"
  port: 27200
vault:
  path: "/tmp/test-vault.db"
events:
  db_path: "/tmp/events.db"
  batch_size: 100
  flush_interval: 5s
  collector_url: "http://127.0.0.1:8090"
  collector_token: "system-token"
  collector_routes:
    personal: "http://127.0.0.1:8090"
    team:     "http://127.0.0.1:8090"
    oauth:    "http://127.0.0.1:8090"
  queue_capacity: 10000
  upload_batch_size: 5
  upload_interval: 5s
  wal_dir: "/tmp/wal"
  control_url: "http://127.0.0.1:8090"
  service_token: "system-token"
log:
  level: info
`

// writeTestPair writes a system yaml + an optional user yaml in a temp
// dir and returns the path to the system file (the Load() input).
func writeTestPair(t *testing.T, system, user string) string {
	t.Helper()
	dir := t.TempDir()
	sysPath := filepath.Join(dir, "aikey-proxy.yaml")
	if err := os.WriteFile(sysPath, []byte(system), 0o644); err != nil {
		t.Fatalf("write system yaml: %v", err)
	}
	if user != "" {
		userPath := filepath.Join(dir, "aikey-user.yaml")
		if err := os.WriteFile(userPath, []byte(user), 0o644); err != nil {
			t.Fatalf("write user yaml: %v", err)
		}
	}
	return sysPath
}

// Without aikey-user.yaml the system value passes through unchanged —
// pre-login state for fresh Personal installs must keep working.
func TestLoad_NoUserYamlPreservesSystemValues(t *testing.T) {
	sysPath := writeTestPair(t, systemProxyYaml, "")
	cfg, err := Load(sysPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Events.CollectorRoutes["team"]; got != "http://127.0.0.1:8090" {
		t.Fatalf("team route should equal system default when no user file: got %q", got)
	}
	if cfg.Events.CollectorToken != "system-token" {
		t.Fatalf("collector_token mangled by no-user-file path: %q", cfg.Events.CollectorToken)
	}
}

// The actual F1 contract: user-layer `proxy.events.collector_routes.team`
// wins on field collision while leaving sibling routes (personal, oauth)
// and other events fields untouched. This is what makes the team override
// survive `make restart-personal`'s re-render of the system yaml.
func TestLoad_UserYamlOverridesTeamRoute(t *testing.T) {
	const userYaml = `
proxy:
  events:
    collector_routes:
      team: "http://192.168.0.113:3000"
`
	sysPath := writeTestPair(t, systemProxyYaml, userYaml)
	cfg, err := Load(sysPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Events.CollectorRoutes["team"]; got != "http://192.168.0.113:3000" {
		t.Fatalf("user-layer team override lost: got %q", got)
	}
	if got := cfg.Events.CollectorRoutes["personal"]; got != "http://127.0.0.1:8090" {
		t.Fatalf("personal route should keep system value: got %q", got)
	}
	if got := cfg.Events.CollectorRoutes["oauth"]; got != "http://127.0.0.1:8090" {
		t.Fatalf("oauth route should keep system value: got %q", got)
	}
	if cfg.Events.CollectorToken != "system-token" {
		t.Fatalf("unrelated event fields mangled by merge: token=%q", cfg.Events.CollectorToken)
	}
}

// A user file that only declares non-proxy sections (e.g. `trial:` for
// jwt_secret) must not affect proxy config — common state on shared
// machines that run both Personal and Trial editions.
func TestLoad_UserYamlWithoutProxySectionIsNoOp(t *testing.T) {
	const userYaml = `
trial:
  jwt_secret: "irrelevant-to-proxy"
  service_token: "also-irrelevant"
`
	sysPath := writeTestPair(t, systemProxyYaml, userYaml)
	cfg, err := Load(sysPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Events.CollectorRoutes["team"]; got != "http://127.0.0.1:8090" {
		t.Fatalf("trial-only user file should not touch proxy routes: got team=%q", got)
	}
}

// Empty user file is the "user file created but no fields yet" edge case.
// Should be treated the same as a missing file (no error, system wins).
func TestLoad_EmptyUserYamlIsNoOp(t *testing.T) {
	sysPath := writeTestPair(t, systemProxyYaml, "")
	// Re-write an explicit empty user file alongside the system file.
	userPath := filepath.Join(filepath.Dir(sysPath), "aikey-user.yaml")
	if err := os.WriteFile(userPath, []byte(""), 0o644); err != nil {
		t.Fatalf("write empty user yaml: %v", err)
	}
	cfg, err := Load(sysPath)
	if err != nil {
		t.Fatalf("Load with empty user yaml: %v", err)
	}
	if got := cfg.Events.CollectorRoutes["team"]; got != "http://127.0.0.1:8090" {
		t.Fatalf("empty user file shouldn't override anything: got team=%q", got)
	}
}
