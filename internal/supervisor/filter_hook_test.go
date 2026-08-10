package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// resolveAppBinary picks the first installed <appsDir>/<slug>/bin/<slug> — the
// convention `aikey app install` lays the detector down at, and what the
// supervisor spawns when the vault declares a filter app (P1).
func TestResolveAppBinary(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "myfilter", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Lay the binary down under the SAME OS-native name `aikey app install` uses
	// (myfilter.exe on Windows, myfilter elsewhere) — the bug was the resolver
	// looking for the extensionless name on Windows and missing the installed
	// .exe. Using appBinaryFileName here keeps the test honest cross-platform.
	bin := filepath.Join(binDir, appBinaryFileName("myfilter"))
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got, slug := resolveAppBinary(dir, []string{"myfilter"}); got != bin || slug != "myfilter" {
		t.Errorf("resolve = (%q,%q), want (%q,myfilter)", got, slug, bin)
	}
	if got, slug := resolveAppBinary(dir, []string{"absent"}); got != "" || slug != "" {
		t.Errorf("absent slug should be empty, got (%q,%q)", got, slug)
	}
	if got, slug := resolveAppBinary(dir, []string{"absent", "myfilter"}); got != bin || slug != "myfilter" {
		t.Errorf("should find the second slug, got (%q,%q)", got, slug)
	}
	// a directory at the binary path must NOT count as a binary.
	_ = os.MkdirAll(filepath.Join(dir, "dirapp", "bin", appBinaryFileName("dirapp")), 0o755)
	if got, _ := resolveAppBinary(dir, []string{"dirapp"}); got != "" {
		t.Errorf("a dir is not a binary, got %q", got)
	}
}

// appBinaryFileName must match the OS-native name the installer writes: bare on
// Unix, .exe on Windows. The Windows arm is the regression guard for the
// 2026-06-23 bug where an extensionless lookup missed the installed
// ai-compliance-detector.exe and latched the proxy into fail-loud 501.
func TestAppBinaryFileName(t *testing.T) {
	got := appBinaryFileName("ai-compliance-detector")
	want := "ai-compliance-detector"
	if runtime.GOOS == "windows" {
		want = "ai-compliance-detector.exe"
	}
	if got != want {
		t.Errorf("appBinaryFileName=%q want %q (GOOS=%s)", got, want, runtime.GOOS)
	}
}

// appsDir derives <home>/.aikey/apps from the vault path <home>/.aikey/data/vault.db.
func TestSupervisorAppsDir(t *testing.T) {
	s := &Supervisor{cfg: &config.Config{Vault: config.VaultConfig{
		Path: filepath.FromSlash("/home/u/.aikey/data/vault.db"),
	}}}
	want := filepath.FromSlash("/home/u/.aikey/apps")
	if got := s.appsDir(); got != want {
		t.Errorf("appsDir = %q, want %q", got, want)
	}
}

// filterTimeout resolves env override → default. Covers default, valid, and
// invalid/zero (must fall back, never use a bad value that would silently
// disable masking via fail-open).
func TestFilterTimeout(t *testing.T) {
	cases := []struct {
		name string
		env  string
		set  bool
		want time.Duration
	}{
		{"unset_uses_default", "", false, filterDefaultTimeout},
		{"empty_uses_default", "", true, filterDefaultTimeout},
		{"valid_override", "150", true, 150 * time.Millisecond},
		{"invalid_uses_default", "abc", true, filterDefaultTimeout},
		{"zero_uses_default", "0", true, filterDefaultTimeout},
		{"negative_uses_default", "-5", true, filterDefaultTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(filterTimeoutMsEnv, tc.env)
			} else {
				t.Setenv(filterTimeoutMsEnv, "") // isolate from ambient env
			}
			if got := filterTimeout(); got != tc.want {
				t.Errorf("filterTimeout()=%v want %v", got, tc.want)
			}
		})
	}
}

// installFilterHook with an explicit-but-missing binary must fail loud: NO hook
// wired into the proxy (FilterHook stays nil), and the helper returns nil (no
// live child to tear down). The proxy's fail-loud 501 path is engaged via
// SetFilterStub501Active — we assert the hook is NOT installed, which is the
// observable half of "don't silently pass traffic through a dead filter".
func TestInstallFilterHook_SpawnFailure_FailsLoud(t *testing.T) {
	t.Setenv(filterBinaryEnv, "/nonexistent/aikey-compliance-detector-xyz")
	t.Setenv(filterArgsEnv, "")
	t.Setenv(filterTimeoutMsEnv, "")

	s := &Supervisor{ctx: context.Background()}
	p := &proxy.Proxy{}

	hook := s.installFilterHook(p, nil) // vault not consulted on the env path
	if hook != nil {
		t.Errorf("expected nil hook on spawn failure, got %v", hook)
	}
	if p.FilterHook() != nil {
		t.Error("filter hook must NOT be installed when the binary can't spawn")
	}
}

// (The vault-declared-but-no-binary outcome consults a *vault.Reader and is
// covered by the integration-level buildGeneration tests, not here — building
// a real vault Reader for a unit test would only re-exercise vault code.)

// Cluster regression (2026-06-17): a cluster node has no Personal config.json;
// its control URL comes from AIKEY_HUB_CONTROL_URL (cluster-node.env), like
// complianceOrgID()'s AIKEY_HUB_ORG_ID. readControlPanelURL() must honor that
// env (trailing slash trimmed), else the conversation-audit + compliance
// master-policy polls early-return on cluster nodes and capture never turns on.
// Bugfix: workflow/CI/bugfix/2026-06-17-conversation-audit-cluster-control-url-env.md
func TestReadControlPanelURL_ClusterEnvFallback(t *testing.T) {
	t.Setenv("AIKEY_HUB_CONTROL_URL", "http://10.0.0.89:8080/")
	if got := readControlPanelURL(); got != "http://10.0.0.89:8080" {
		t.Fatalf("cluster AIKEY_HUB_CONTROL_URL env not honored (trailing-slash-trimmed): got %q", got)
	}
}

// TestFilterScanRoles_Env covers the P4 scan-role override (方案 §3.4). The
// load-bearing case is `unset` → nil → the proxy's DEFAULT {user, assistant}:
// a fleet that never sets this env must still scan assistant history, otherwise
// the placeholder-restore leak (方案 §2.2) is open in production.
func TestFilterScanRoles_Env(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want []string
	}{
		{"unset_means_default", "", nil},
		{"single", "user", []string{"user"}},
		{"pair", "user,assistant", []string{"user", "assistant"}},
		// Per-entry trimming/lowercasing is the proxy's job (newScanRoleSet); the
		// env helper only trims the whole value and splits on commas.
		{"spaces_and_case_passed_through", " User , ASSISTANT ", []string{"User ", " ASSISTANT"}},
		{"extension_slot", "user,assistant,tool", []string{"user", "assistant", "tool"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(filterScanRolesEnv, tc.env)
			got := filterScanRoles()
			if len(got) != len(tc.want) {
				t.Fatalf("filterScanRoles()=%q want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("filterScanRoles()=%q want %q", got, tc.want)
				}
			}
		})
	}
}

// The env → proxy round-trip: whatever the operator writes, the proxy must end
// up with a policy that still includes assistant unless it was deliberately
// removed — and an all-garbage value must fall back to the default, not to
// "scan nothing".
func TestFilterScanRoles_AppliedToProxy(t *testing.T) {
	cases := []struct {
		name        string
		env         string
		wantApplied []string
		wantReject  int
	}{
		{"unset_default", "", []string{"assistant", "user"}, 0},
		{"widened", "user,assistant,tool", []string{"assistant", "tool", "user"}, 0},
		{"narrowed", "user", []string{"user"}, 0},
		{"typo_is_reported_not_swallowed", "user,assistnat", []string{"user"}, 1},
		{"all_garbage_falls_back_to_default", "nope,zzz", []string{"assistant", "user"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(filterScanRolesEnv, tc.env)
			p := &proxy.Proxy{}
			applied, rejected := p.SetFilterScanRoles(filterScanRoles())
			if len(rejected) != tc.wantReject {
				t.Errorf("rejected=%q want %d entries", rejected, tc.wantReject)
			}
			if len(applied) != len(tc.wantApplied) {
				t.Fatalf("applied=%q want %q", applied, tc.wantApplied)
			}
			for i := range applied {
				if applied[i] != tc.wantApplied[i] {
					t.Fatalf("applied=%q want %q", applied, tc.wantApplied)
				}
			}
		})
	}
}
