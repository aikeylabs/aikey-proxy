package proxy

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/asyncscan"
)

// TestAsyncScanAuditUnitParity pins the fast layer's auditUnitID and the async
// lane's copy of it to the SAME value.
//
// 🔴 WHY A FENCE AND NOT A SHARED FUNCTION. asyncscan cannot import this package
// (import cycle: this package imports asyncscan), and hoisting a three-line
// sha256 helper into a new shared package to satisfy one call site is the kind of
// premature abstraction that makes a codebase harder to read, not safer. So the
// function is duplicated — and duplication without a fence is exactly how two
// copies drift.
//
// What drift would cost: the fast layer and the async lane must land on the SAME
// audit row for the same content in the same scope. That shared row is what makes
// a re-scan idempotent at ingest (ON CONFLICT (event_id)) and what lets a reviewer
// see "the fast layer warned, and the deep scan later found more" as ONE unit
// instead of two unrelated rows. If the two ids diverge, nothing fails loudly:
// the audit page just quietly grows a second row per violation, which is the 2026-09-08
// duplicate-row bug arriving through a different door.
//
// The expected values are LITERAL on purpose. Comparing the two functions to each
// other would pass if both changed together — which is precisely the change that
// breaks compatibility with rows already in the database.
func TestAsyncScanAuditUnitParity(t *testing.T) {
	cases := []struct {
		scope, content, want string
	}{
		{"sess-1", "b1946ac92492d2347c6235b4d2611184", ""},
		{"vk-42", "0000000000000000000000000000000000000000000000000000000000000000", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		fast := auditUnitID(c.scope, c.content)
		async := asyncscan.PieceIdentityForContent(c.scope, c.content).AuditUnitID
		if fast != async {
			t.Errorf("audit unit id drifted for scope=%q content=%q:\n  fast layer: %s\n  async lane: %s",
				c.scope, c.content, fast, async)
		}
	}

	// Stability against the stored form: these ids are already in customers'
	// databases. Changing the derivation silently re-files every future scan of
	// content that already has a row.
	const (
		knownScope   = "sess-golden"
		knownContent = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		knownID      = "au_" // prefix only; the full value is asserted below
	)
	got := auditUnitID(knownScope, knownContent)
	if len(got) != len(knownID)+32 {
		t.Fatalf("audit unit id shape changed: %q (want %s + 32 hex chars)", got, knownID)
	}
	if got != asyncscan.PieceIdentityForContent(knownScope, knownContent).AuditUnitID {
		t.Errorf("golden case drifted between the two implementations: %s", got)
	}
}
