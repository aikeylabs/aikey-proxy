package supervisor

// Golden cases test for NormalizeTeamToken (Go side).
//
// Loads the same fixture as the Rust side at
// `aikey-cli/tests/fixtures/team_token_normalize.json` (relative to repo root)
// and asserts every case. Both implementations must produce identical results
// across the same fixture — guards against long-term drift.
//
// Spec: roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md §4.

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type fixtureCase struct {
	ExpectedOK  *string `json:"expected_ok"`
	ExpectedErr *string `json:"expected_err"`
	Name        string  `json:"name"`
	Input       string  `json:"input"`
}

type fixture struct {
	Cases []fixtureCase `json:"cases"`
}

// repoRoot resolves the monorepo root by walking up from CWD until a `.git`
// directory is found. Returns "" on failure.
//
// Why not `embed`: Go's `//go:embed` cannot reference files outside the
// containing package directory, so we cannot embed
// `aikey-cli/tests/fixtures/...` from this Go package. Use OS file read with
// repo-root resolution instead.
func repoRoot(t *testing.T) string {
	t.Helper()
	// First try git rev-parse (most reliable).
	if out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output(); err == nil {
		root := strings.TrimSpace(string(out))
		// rev-parse returns the closest .git ancestor, which may be aikey-proxy
		// if that's its own repo. Look for the monorepo root by name.
		if filepath.Base(root) == "aikeylabs" {
			return root
		}
		// Walk up until we find aikeylabs/ as a parent
		dir := root
		for dir != "/" && dir != "." {
			if filepath.Base(dir) == "aikeylabs" {
				return dir
			}
			dir = filepath.Dir(dir)
		}
	}
	// Fallback: walk up from CWD looking for the fixture file directly.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	dir := cwd
	for dir != "/" && dir != "." {
		candidate := filepath.Join(dir, "aikey-cli", "tests", "fixtures", "team_token_normalize.json")
		if _, err := os.Stat(candidate); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	root := repoRoot(t)
	if root == "" {
		t.Fatalf("could not resolve monorepo root for fixture")
	}
	path := filepath.Join(root, "aikey-cli", "tests", "fixtures", "team_token_normalize.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var fx fixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fx.Cases) == 0 {
		t.Fatalf("fixture must contain at least one case")
	}
	return fx
}

func TestNormalizeTeamToken_GoldenCases(t *testing.T) {
	fx := loadFixture(t)
	var failed []string

	for _, c := range fx.Cases {
		got, err := NormalizeTeamToken(c.Input)
		switch {
		case c.ExpectedOK != nil && c.ExpectedErr == nil:
			if err != nil {
				failed = append(failed, c.Name+": expected ok, got err: "+err.Error())
			} else if got != *c.ExpectedOK {
				failed = append(failed, c.Name+": expected "+*c.ExpectedOK+", got "+got)
			}
		case c.ExpectedErr != nil && c.ExpectedOK == nil:
			if err == nil {
				failed = append(failed, c.Name+": expected err "+*c.ExpectedErr+", got ok: "+got)
			} else if err.Error() != *c.ExpectedErr {
				failed = append(failed, c.Name+": expected err "+*c.ExpectedErr+", got "+err.Error())
			}
		default:
			failed = append(failed, c.Name+": malformed fixture case (must have exactly one of expected_ok / expected_err)")
		}
	}

	if len(failed) > 0 {
		t.Fatalf("%d golden case(s) failed:\n%s", len(failed), strings.Join(failed, "\n"))
	}
}

func TestNormalizeTeamToken_ErrIsExported(t *testing.T) {
	// 调用方需要能用 errors.Is(err, ErrEmptyVkID) 区分空串错误，确保 ErrEmptyVkID
	// 是 sentinel error 而非每次新建。
	_, err := NormalizeTeamToken("")
	if !errors.Is(err, ErrEmptyVkID) {
		t.Fatalf("expected errors.Is(err, ErrEmptyVkID) true, got err = %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// isStrictPersonalRouteToken — registry-load filter for legacy residue
// ─────────────────────────────────────────────────────────────────────
//
// Pins the contract: only `aikey_personal_` + 64 lowercase hex passes.
// Catches the regression where supervisor would silently re-register
// pre-migration `aikey_vk_<64-hex>` route tokens (review #1, 2026-04-29).

func TestIsStrictPersonalRouteToken_AcceptsNewBearerForm(t *testing.T) {
	cases := []string{
		"aikey_personal_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"aikey_personal_" + strings.Repeat("0", 64),
		"aikey_personal_" + strings.Repeat("f", 64),
		"aikey_personal_" + strings.Repeat("a", 32) + strings.Repeat("9", 32),
	}
	for _, tok := range cases {
		if !isStrictPersonalRouteToken(tok) {
			t.Errorf("isStrictPersonalRouteToken(%q) = false, want true", tok)
		}
	}
}

func TestIsStrictPersonalRouteToken_RejectsLegacyAndMalformed(t *testing.T) {
	cases := []struct {
		name string
		tok  string
	}{
		{"legacy aikey_vk_ prefix", "aikey_vk_" + strings.Repeat("a", 64)},
		{"63 hex (short)", "aikey_personal_" + strings.Repeat("0", 63)},
		{"65 hex (long)", "aikey_personal_" + strings.Repeat("0", 65)},
		{"uppercase hex", "aikey_personal_" + strings.Repeat("A", 64)},
		{"non-hex letter g", "aikey_personal_" + strings.Repeat("g", 64)},
		{"with hyphen in suffix", "aikey_personal_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde-"},
		{"legacy alias form", "aikey_personal_my-claude"},
		{"empty suffix", "aikey_personal_"},
		{"empty token", ""},
		{"native sk-", "sk-1234567890"},
		{"team prefix", "aikey_team_acc-1234"},
		{"reserved aikey_route_*", "aikey_route_" + strings.Repeat("0", 64)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if isStrictPersonalRouteToken(c.tok) {
				t.Errorf("isStrictPersonalRouteToken(%q) = true, want false (must be filtered out at registry load)", c.tok)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// tokenPrefixForLog — never leak full token bytes into logs
// ─────────────────────────────────────────────────────────────────────

func TestTokenPrefixForLog_DoesNotLeakSuffix(t *testing.T) {
	cases := map[string]string{
		"aikey_personal_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": "aikey_personal_...",
		"aikey_vk_acc-1234abc":   "aikey_vk_...",
		"aikey_team_my-team":     "aikey_team_...",
		"aikey_unknown_xyz":      "aikey_unknown_...",
		"":                       "<empty>",
		"sk-real-secret-payload": "<no-aikey-prefix>",
		"aikey_personal_short":   "aikey_personal_...", // legacy alias form — still log just the prefix segment
	}
	for input, want := range cases {
		got := tokenPrefixForLog(input)
		if got != want {
			t.Errorf("tokenPrefixForLog(%q) = %q, want %q", input, got, want)
		}
		// CRITICAL invariant: full bytes after the second underscore must NOT appear.
		// Don't apply this check to short non-aikey or empty inputs.
		if strings.HasPrefix(input, "aikey_") {
			parts := strings.SplitN(strings.TrimPrefix(input, "aikey_"), "_", 2)
			if len(parts) == 2 && parts[1] != "" && strings.Contains(got, parts[1]) {
				t.Errorf("token suffix %q leaked into log representation %q (input=%q)", parts[1], got, input)
			}
		}
	}
}
