package vault

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoRawSQLOpenInVault is a source-scan fence for the busy_timeout mandate.
//
// Why: modernc's default busy_timeout is 0, so any raw sql.Open against the
// shared vault fails instantly with SQLITE_BUSY under a concurrent reader and
// the write is silently dropped. This regressed twice by hand-audit misses
// (2026-07-03 R2: five raw opens; 2026-07-07 parity audit P1-4:
// WriteAssignmentOverride left behind). A structural scan cannot miss the
// eighth site the way a human can.
func TestNoRawSQLOpenInVault(t *testing.T) {
	openCall := regexp.MustCompile(`sql\.Open\(\s*"sqlite"\s*,\s*([^)]*)\)`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range openCall.FindAllStringSubmatch(string(src), -1) {
			arg := strings.TrimSpace(m[1])
			if !strings.HasPrefix(arg, "WithBusyTimeoutDSN(") {
				t.Errorf("%s: raw sql.Open DSN %q — wrap it with WithBusyTimeoutDSN (busy_timeout is mandatory for all vault opens, see WriteGroupRuntime comment)", name, arg)
			}
		}
	}
}
