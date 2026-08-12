//go:build integration

package supervisor

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

func TestFilterIntegration_MaxActionFullWarnFullFromVault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AIKEY_HUB_CONTROL_URL", "")
	t.Setenv(filterBinaryEnv, "")
	t.Setenv(filterWorkersEnv, "1")

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration test source path")
	}
	labsRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	cliBinary := os.Getenv("AIKEY_CLI_TEST_BIN")
	if cliBinary == "" {
		cliBinary = filepath.Join(labsRoot, "aikey-cli", "target", "debug", "aikey")
	}
	if info, err := os.Stat(cliBinary); err != nil || info.IsDir() {
		t.Fatalf("real CLI binary missing at %s; run `make filter-integration`: %v", cliBinary, err)
	}

	const vaultPassword = "compliance-migration-integration-password"
	runCLI := func(args ...string) {
		t.Helper()
		cmd := exec.Command(cliBinary, args...)
		cmd.Dir = home
		cmd.Env = append(os.Environ(),
			"HOME="+home,
			"AK_TEST_PASSWORD="+vaultPassword,
			"AIKEY_MASTER_PASSWORD="+vaultPassword,
			"AK_TEST_SECRET=bootstrap-not-a-provider-key",
			"AIKEY_NO_HOOK=1",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("real CLI %v failed: %v\n%s", args, err, output)
		}
	}
	// A write command drives the canonical Rust initialize_vault + migration
	// chain. Read-only commands intentionally do not create a fresh Vault.
	runCLI("add", "__compliance_migration_bootstrap__", "--provider", "openai")
	runCLI("delete", "__compliance_migration_bootstrap__")

	dbPath := filepath.Join(home, ".aikey", "data", "vault.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO app_records
		(slug, name, vendor, upstreams, app_kind, filter_stages)
		VALUES ('ai-compliance-detector', 'AI Compliance Detector', 'AiKey Labs', '[]', 'first-party', '["pre_forward"]')`); err != nil {
		t.Fatal(err)
	}
	reader, err := vault.Open(dbPath, vaultPassword)
	if err != nil {
		t.Fatalf("Proxy could not open the real CLI-migrated Vault: %v", err)
	}
	t.Cleanup(func() { reader.Close() })

	detectorBinary := filepath.Join(labsRoot, "ai-compliance-detector", "bin", "detector")
	if info, err := os.Stat(detectorBinary); err != nil || info.IsDir() {
		t.Fatalf("real detector binary missing at %s; run sibling build: %v", detectorBinary, err)
	}
	installedBinary := filepath.Join(filepath.Dir(filepath.Dir(dbPath)), "apps", complianceDetectorSlug, "bin", complianceDetectorSlug)
	if err := os.MkdirAll(filepath.Dir(installedBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(detectorBinary, installedBinary); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Vault.Path = dbPath
	s := &Supervisor{cfg: cfg, ctx: context.Background()}
	request := &apphook.Request{
		Payload:     []byte("here you go AKIA" + strings.Repeat("Q", 16) + " keep it safe"),
		Direction:   apphook.DirectionInbound,
		RouteClass:  apphook.RouteClassTeam,
		RequestID:   "max-action-live",
		TargetModel: "resident-mock-provider",
	}

	evaluateAfterRespawn := func(want apphook.Action) {
		t.Helper()
		p := &proxy.Proxy{}
		target := s.installFilterHook(p, reader)
		if target == nil {
			t.Fatal("real detector child was not installed")
		}
		response := target.Detect(context.Background(), request)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := target.Shutdown(shutdownCtx); err != nil {
			t.Fatalf("shutdown detector child: %v", err)
		}
		if response.Degraded || response.Action != want {
			t.Fatalf("live action=%s degraded=%v reason=%q; want %s", response.Action, response.Degraded, response.Reason, want)
		}
		if len(response.Event) == 0 {
			t.Fatal("team-routed rollback probe did not produce a new compliance event")
		}
	}

	evaluateAfterRespawn(apphook.ActionBlock)
	if _, err := db.Exec(`UPDATE app_records SET filter_max_action='warn' WHERE slug='ai-compliance-detector'`); err != nil {
		t.Fatal(err)
	}
	evaluateAfterRespawn(apphook.ActionWarn)
	if _, err := db.Exec(`UPDATE app_records SET filter_max_action='full' WHERE slug='ai-compliance-detector'`); err != nil {
		t.Fatal(err)
	}
	evaluateAfterRespawn(apphook.ActionBlock)
	var preservedStages string
	if err := db.QueryRow(`SELECT filter_stages FROM app_records WHERE slug='ai-compliance-detector'`).Scan(&preservedStages); err != nil {
		t.Fatalf("read pre-existing app data after rollback drill: %v", err)
	}
	if preservedStages != `["pre_forward"]` {
		t.Fatalf("pre-existing app data changed during rollback drill: %q", preservedStages)
	}
}
