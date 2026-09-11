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

// An operator-supplied path must be honored verbatim (after `~` expansion),
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

// Cluster mode lifts the loopback-only listen restriction: a cluster node must
// be network-reachable (0.0.0.0). Non-cluster (Personal/Trial) keeps loopback-only.
func TestValidate_ClusterAllowsNonLoopbackListen(t *testing.T) {
	base := func() *Config {
		c := &Config{}
		c.Listen.Host = "0.0.0.0"
		c.Listen.Port = 27200
		return c
	}

	// non-cluster + 0.0.0.0 → rejected
	if err := base().validate(); err == nil {
		t.Fatal("non-cluster 0.0.0.0 listen should be rejected (loopback-only safety rail)")
	}

	// cluster + 0.0.0.0 → allowed (still needs the other cluster fields)
	c := base()
	c.Cluster.Enabled = true
	c.Cluster.HubURL = "http://hub:27400"
	c.Cluster.NodeID = "node-1"
	c.Cluster.NodeAddr = "node:27200"
	if err := c.validate(); err != nil {
		t.Fatalf("cluster 0.0.0.0 listen should be allowed, got: %v", err)
	}

	// cluster enabled but missing required fields → rejected
	bad := base()
	bad.Cluster.Enabled = true // no hub_url/node_id/node_addr
	if err := bad.validate(); err == nil {
		t.Fatal("cluster.enabled without hub_url/node_id/node_addr should be rejected")
	}
}

// ── 2026-05-11 F1 fix: aikey-user.yaml proxy: section merge ───────────────
//
// Load() now reads aikey-user.yaml from the same directory and merges its
// `proxy:` subtree on top of the system yaml. These tests pin the merge
// behavior we depend on so a future refactor that drops or weakens it
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
//
// alternate system-yaml shapes without re-plumbing the helper.
//
//nolint:unparam // `system` kept parameterized so future cases can probe
func writeTestPair(t *testing.T, system, user string) string {
	t.Helper()
	dir := t.TempDir()
	sysPath := filepath.Join(dir, "aikey-proxy.yaml")
	if err := os.WriteFile(sysPath, []byte(system), 0o600); err != nil {
		t.Fatalf("write system yaml: %v", err)
	}
	if user != "" {
		userPath := filepath.Join(dir, "aikey-user.yaml")
		if err := os.WriteFile(userPath, []byte(user), 0o600); err != nil {
			t.Fatalf("write user yaml: %v", err)
		}
	}
	return sysPath
}

// Without aikey-user.yaml the system value passes through unchanged —
// pre-login state for fresh Personal installs must keep working.
// console_url absent-vs-empty contract (20260703 OAuth组成员登录提示):
// ABSENT key = pre-20260703 config preserved across an upgrade → must default
// (the whole existing personal/trial install base gets the login URL without a
// config migration). EXPLICIT "" = server/cluster opt-out → must stay empty.
// A plain-string "simplification" would silently break the upgrade default.
func TestLoad_ConsoleURLAbsentDefaultsExplicitEmptyHonored(t *testing.T) {
	// systemProxyYaml predates console_url — the upgrade-preserved shape.
	sysPath := writeTestPair(t, systemProxyYaml, "")
	cfg, err := Load(sysPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.ResolvedConsoleURL(); got != DefaultConsoleURL {
		t.Fatalf("absent console_url must default to %q, got %q", DefaultConsoleURL, got)
	}

	sysPath2 := writeTestPair(t, systemProxyYaml+"\nconsole_url: \"\"\n", "")
	cfg2, err := Load(sysPath2)
	if err != nil {
		t.Fatalf("Load explicit-empty: %v", err)
	}
	if got := cfg2.ResolvedConsoleURL(); got != "" {
		t.Fatalf("explicit-empty console_url must stay empty (opt-out), got %q", got)
	}

	sysPath3 := writeTestPair(t, systemProxyYaml+"\nconsole_url: \"http://127.0.0.1:9191\"\n", "")
	cfg3, err := Load(sysPath3)
	if err != nil {
		t.Fatalf("Load explicit-value: %v", err)
	}
	if got := cfg3.ResolvedConsoleURL(); got != "http://127.0.0.1:9191" {
		t.Fatalf("explicit console_url must be honored, got %q", got)
	}
}

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
	if err := os.WriteFile(userPath, []byte(""), 0o600); err != nil {
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

// TestChatCompletionsBridge_UserLayerOverridesSystem is the fence for a
// delivery trap, not for the parser.
//
// aikey-proxy.yaml is the SYSTEM layer: aikey-config-tool re-renders it from
// the template on every install. An operator who turns the bridge on by
// editing that file would have it silently reverted on the next upgrade — the
// feature would appear to "randomly stop working" with nothing in any log.
// The supported place is aikey-user.yaml's `proxy:` section, which is never
// re-rendered and wins on merge. This test proves that path actually reaches
// Config, so the instruction in the template comment is true.
func TestChatCompletionsBridge_UserLayerOverridesSystem(t *testing.T) {
	dir := t.TempDir()
	sysPath := filepath.Join(dir, "aikey-proxy.yaml")
	if err := os.WriteFile(sysPath, []byte(
		"listen:\n  host: \"127.0.0.1\"\n  port: 27200\n"+
			"vault:\n  path: \"/tmp/v.db\"\n"+
			"chat_completions_bridge:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No user file yet: the system default must hold.
	cfg, err := Load(sysPath)
	if err != nil {
		t.Fatalf("load without user file: %v", err)
	}
	if cfg.ChatCompletionsBridge.Enabled {
		t.Fatal("bridge is on with no user override; off must be the shipped default")
	}

	if err := os.WriteFile(filepath.Join(dir, "aikey-user.yaml"), []byte(
		"proxy:\n  chat_completions_bridge:\n    enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(sysPath)
	if err != nil {
		t.Fatalf("load with user file: %v", err)
	}
	if !cfg.ChatCompletionsBridge.Enabled {
		t.Fatal("the user layer did not reach Config — an operator turning the bridge on " +
			"in aikey-user.yaml would see no effect, and the only writable alternative " +
			"(the system file) is reverted on upgrade")
	}
}

// TestChatCompletionsBridge_UpstreamValidation guards the config surface that
// decides where an OAuth token may be sent.
//
// Every case here fails at STARTUP on purpose. The alternative — noticing at
// the first request that needs it — means a deployment looks healthy until a
// user hits the one credential that is misconfigured, and the symptom
// (wrong-shaped request, or traffic quietly going to the default) points
// nowhere near the config.
func TestChatCompletionsBridge_UpstreamValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		up      []BridgeUpstream
		wantErr string
	}{
		{"valid", []BridgeUpstream{{Host: "relay.example", Dialect: BridgeDialectChatCompletions}}, ""},
		{"valid responses", []BridgeUpstream{{Host: "r.example", Dialect: BridgeDialectResponses}}, ""},
		{"missing host", []BridgeUpstream{{Dialect: BridgeDialectResponses}}, "host is required"},
		{"missing dialect", []BridgeUpstream{{Host: "relay.example"}}, "dialect is required"},
		{"unknown dialect", []BridgeUpstream{{Host: "relay.example", Dialect: "grpc"}}, "unknown dialect"},
		{"scheme in host", []BridgeUpstream{{Host: "https://relay.example", Dialect: BridgeDialectResponses}}, "bare hostname"},
		{"wildcard host", []BridgeUpstream{{Host: "*.example", Dialect: BridgeDialectResponses}}, "bare hostname"},
		{"path in host", []BridgeUpstream{{Host: "relay.example/v1", Dialect: BridgeDialectResponses}}, "bare hostname"},
		{"duplicate host", []BridgeUpstream{
			{Host: "relay.example", Dialect: BridgeDialectResponses},
			{Host: "RELAY.example", Dialect: BridgeDialectChatCompletions},
		}, "listed twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ChatCompletionsBridgeConfig{Enabled: true, Upstreams: tc.up}.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("valid config rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("invalid config accepted (%s)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestChatCompletionsBridge_EmptyIsValid — the shipped default must not need a
// config block at all.
func TestChatCompletionsBridge_EmptyIsValid(t *testing.T) {
	if err := (ChatCompletionsBridgeConfig{}).Validate(); err != nil {
		t.Fatalf("the zero-value bridge config was rejected: %v", err)
	}
}

// TestShippedDefaultConfigsActuallyLoad is a fence over the two files that
// become a customer's configuration.
//
// `aikey-proxy.yaml.example` is copied verbatim into every release bundle as
// `config/default/aikey-proxy.yaml` (release.sh), and `aikey-proxy.yaml` is the
// dev fixture the same shape is maintained against. Until this test existed
// NOTHING parsed either of them: the dev-fixture gate compares top-level key
// NAMES as text, which cannot notice a YAML syntax error, a mis-indented block
// or a value of the wrong type.
//
// The failure that gap allowed is the worst kind for a shipped default: the
// file is fine in review, fine in the gate, and then every FRESH INSTALL fails
// to start — on the customer's machine, at the moment they first try it, with
// nothing in the repo having gone red.
func TestShippedDefaultConfigsActuallyLoad(t *testing.T) {
	for _, name := range []string{"aikey-proxy.yaml", "aikey-proxy.yaml.example"} {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join("..", "..", name)
			if _, err := os.Stat(src); err != nil {
				t.Fatalf("%s is missing; release.sh ships it as the bundle default", name)
			}
			// Copy into a temp dir: Load resolves a sibling aikey-user.yaml, and
			// reading the repo's own directory would make the result depend on
			// whatever a developer happens to have lying next to it.
			dir := t.TempDir()
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(dir, "aikey-proxy.yaml")
			if err := os.WriteFile(dst, data, 0o600); err != nil {
				t.Fatal(err)
			}

			cfg, err := Load(dst)
			if err != nil {
				t.Fatalf("the shipped default config does not load: %v\n"+
					"every fresh install from a release bundle would fail to start", err)
			}

			// A shipped default must never arrive with translation already on:
			// it would mean a customer who asked for nothing gets their prompts
			// and answers rewritten.
			if cfg.ChatCompletionsBridge.Enabled {
				t.Error("the shipped default enables the dialect bridge; it must be opt-in")
			}
			// And it must never arrive pre-authorizing an OAuth destination.
			if len(cfg.ChatCompletionsBridge.Upstreams) != 0 {
				t.Errorf("the shipped default pre-authorizes %d OAuth upstream(s); the allowlist "+
					"must start empty so only the compiled-in destination is reachable",
					len(cfg.ChatCompletionsBridge.Upstreams))
			}
		})
	}
}
