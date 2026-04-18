package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
