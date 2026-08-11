package proxy

import (
	"testing"

	"github.com/AiKeyLabs/aikey-config-tool/pkg/dbmigrate"
	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// ---------------------------------------------------------------------------
// The PRODUCER half of the compliance `action_taken` value-domain fence.
//
// # Why this test exists (2026-08-10, and it cost a whole feature)
//
// 方案② capped tool-block verdicts at `audit` and the proxy started stamping
// that word into the event it uploads (injectActionTaken). The column's CHECK
// IN-list had said ('allow','mask','block','warn') since v1.0.0-rc.6, so every
// one of those events was rejected by PostgreSQL with SQLSTATE 23514. Nothing in
// this repository could have noticed: the value the proxy writes is a plain Go
// string handed to a JSON field, and the constraint that governs it lives in a
// different repository's migration.
//
// # The shape of the fence, and why "assert it equals audit" is NOT the shape
//
// The failure was not "we forgot 'audit'". It was that the set of values this
// code can emit and the set the database accepts were connected by nothing but
// an author's memory. So the assertion is set-membership against the schema's
// own declaration:
//
//	dbmigrate.ComplianceActionTakenValues — the CHECK IN-list, as Go data
//
// aikey-proxy already depends on aikey-config-tool, so the producer can import
// the domain directly. Adding a rung to actionCeiling whose String() is not a
// member turns this red at `go test` time instead of at INSERT time on a
// customer's control plane. The mirror fence
// (aikey-config-tool pkg/dbmigrate/versions_master/
// compliance_action_taken_domain_test.go) asserts the DDL really ends up equal
// to that same slice on both dialects, so neither side can be satisfied alone.
//
// # Why it enumerates REACHABLE values, not every value String() can return
//
// actionCeiling.String() can also return "full" and "off". Neither is a verdict
// and neither can reach the field: injectActionTaken is called only when
// clamp() reports the verdict was downgraded, which ceilingFull never does, and
// a ceilingOff block type is never extracted so no content piece can carry it.
// Asserting on the raw String() range would demand 'full' and 'off' in the
// database's IN-list — polluting a value domain to satisfy a test. A fence that
// forces the schema to describe states that cannot occur is a worse fence than
// none, so this one walks the actual call path.
// ---------------------------------------------------------------------------

// TestActionTakenVocabulary_EveryValueTheProxyCanRecordIsInTheDatabaseDomain
// walks every ceiling reachable by a content piece — the canonical policy rows,
// every tool-scan rung the operator switch can select, and every nesting
// combination tighten() can produce — and checks the value each one would stamp.
func TestActionTakenVocabulary_EveryValueTheProxyCanRecordIsInTheDatabaseDomain(t *testing.T) {
	reachable := reachablePieceCeilings()
	if len(reachable) == 0 {
		t.Fatal("no ceilings enumerated — this fence is vacuous; blockScanPolicy is empty or the enumeration broke")
	}

	verdicts := []apphook.Action{apphook.ActionAllow, apphook.ActionMask, apphook.ActionBlock, apphook.ActionWarn}
	checked := 0
	for _, c := range reachable {
		for _, v := range verdicts {
			if _, capped := c.clamp(v); !capped {
				continue // injectActionTaken is not called on this path
			}
			checked++
			got := c.String()
			if !dbmigrate.IsValidComplianceActionTaken(got) {
				t.Errorf("ceiling %d caps verdict %q and would record action_taken=%q, which the database CHECK does not accept.\n"+
					"  database domain: %v\n"+
					"  Every event on this path will be rejected with SQLSTATE 23514 and the operator will see an EMPTY compliance dashboard while the content still reaches the LLM vendor — the 2026-08-10 failure, exactly.\n"+
					"  Fix: ship a migration relaxing the CHECK and add the value to dbmigrate.ComplianceActionTakenValues (both, in that order). Do not rename the rung to dodge this test.",
					c, v, got, dbmigrate.ComplianceActionTakenValues)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no (ceiling, verdict) pair actually capped anything — the fence walked the wrong path and would not have caught the 2026-08-10 defect")
	}

	// Non-vacuity: the membership helper must be capable of saying no. Without
	// this, a future refactor that made IsValidComplianceActionTaken always
	// return true would leave every assertion above passing.
	for _, notAVerdict := range []string{"full", "off", ""} {
		if dbmigrate.IsValidComplianceActionTaken(notAVerdict) {
			t.Errorf("the domain accepts %q, which is a ceiling name (or empty), not a verdict — the value domain has been widened to include non-outcomes", notAVerdict)
		}
	}
}

// TestActionTakenVocabulary_DetectorVerdictsAreAllInTheDatabaseDomain covers the
// UNCAPPED path. When nothing is capped the proxy forwards the detector's own
// `action_taken` untouched, so the detector's verdict ladder — mirrored in this
// repo as apphook.Action — is just as much a producer of the column.
func TestActionTakenVocabulary_DetectorVerdictsAreAllInTheDatabaseDomain(t *testing.T) {
	for _, a := range []apphook.Action{apphook.ActionAllow, apphook.ActionMask, apphook.ActionBlock, apphook.ActionWarn} {
		if !dbmigrate.IsValidComplianceActionTaken(a.String()) {
			t.Errorf("apphook.Action %q is a verdict the detector can return and the proxy forwards verbatim, but the database CHECK does not accept it.\n  database domain: %v",
				a.String(), dbmigrate.ComplianceActionTakenValues)
		}
	}
}

// reachablePieceCeilings returns every actionCeiling a contentPiece can end up
// carrying. Derived from the policy table rather than hand-listed, so a new
// block type or a new operator rung is covered automatically — the property
// TestLint_MigrationDialectLintCoversNewMigrationsAutomatically pins on the
// schema side.
func reachablePieceCeilings() []actionCeiling {
	seen := map[actionCeiling]bool{}
	add := func(c actionCeiling) { seen[c] = true }

	// Every rung the tool-block operator switch can put the tool rows at, and the
	// policy table built at each one. buildBlockScanPolicy is the single literal
	// of the table, so this covers the canonical rows too.
	for _, mode := range []toolBlockScanMode{toolBlockScanAudit, toolBlockScanOff} {
		for _, rule := range buildBlockScanPolicy(toolBlockCeilingFor(mode)) {
			add(rule.ceiling)
		}
	}
	// Nesting takes the minimum of the inherited and the row ceiling, so every
	// pairwise tightening is also reachable (text inside a tool_result, etc.).
	base := make([]actionCeiling, 0, len(seen))
	for c := range seen {
		base = append(base, c)
	}
	for _, a := range base {
		for _, b := range base {
			add(a.tighten(b))
		}
	}

	// 🔴 Mirror of the walker's ONE gate (collectContentField:
	// `if eff == ceilingOff { continue }`): a row resolved to ceilingOff is
	// skipped before rule.extract runs, so it yields no contentPiece and its
	// String() ("off") can never reach action_taken. Dropping it here is what
	// keeps the fence honest — including it would demand the database's value
	// domain carry a state that cannot occur.
	//
	// If that gate ever moves, this filter is wrong and the fence starts
	// under-reporting. The gate's location is asserted by
	// TestBlockScanPolicy_* in filter_toolblock_test.go.
	out := make([]actionCeiling, 0, len(seen))
	for c := range seen {
		if c == ceilingOff {
			continue
		}
		out = append(out, c)
	}
	return out
}
