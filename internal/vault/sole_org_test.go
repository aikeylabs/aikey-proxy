package vault

// sole_org_test.go — SoleOrgID must REFUSE rather than choose (2026-07-31).
//
// A cluster node derives the org it serves from its own cache, so the policy
// rail can authenticate with a node service token instead of a team JWT it can
// never have. The value picks which organization's thresholds this node applies
// — attempt timeout, chain budget, cooldown — so a wrong answer silently governs
// whose requests get cut off and when.
//
// 🔴 Every failure mode here therefore returns ok=false. "Not yet known" and
// "ambiguous" must both leave the node on its builtin defaults, which are safe
// and visible (`source: builtin` on /status), rather than on another org's
// numbers, which would look correct and be wrong.

import (
	"database/sql"
	"testing"
)

func orgVault(t *testing.T, orgs ...string) *Reader {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE managed_virtual_keys_cache (
		virtual_key_id TEXT, alias TEXT, org_id TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i, o := range orgs {
		if _, err := db.Exec(
			`INSERT INTO managed_virtual_keys_cache (virtual_key_id, alias, org_id) VALUES (?,?,?)`,
			"vk", "a", o); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	return &Reader{db: db}
}

func TestSoleOrgID_OneOrgIsResolved(t *testing.T) {
	got, ok := orgVault(t, "org-1", "org-1").SoleOrgID()
	if !ok || got != "org-1" {
		t.Fatalf("SoleOrgID = (%q, %v), want (\"org-1\", true) — a node provisioned for one "+
			"org must be able to name it, or its policy rail cannot authenticate at all", got, ok)
	}
}

func TestSoleOrgID_RefusesWhenAmbiguous(t *testing.T) {
	got, ok := orgVault(t, "org-1", "org-2").SoleOrgID()
	if ok {
		t.Fatalf("SoleOrgID returned %q for a vault holding two organizations. Choosing one "+
			"points this node's timeouts, cooldown and chain budget at an org picked by row "+
			"order — it would look configured and govern the wrong tenant's traffic", got)
	}
}

func TestSoleOrgID_RefusesWhenEmpty(t *testing.T) {
	if got, ok := orgVault(t).SoleOrgID(); ok {
		t.Fatalf("SoleOrgID = %q on an empty cache; a node that has not pulled a key yet does "+
			"not know its org, and that is 'not yet', not an answer", got)
	}
}

func TestSoleOrgID_IgnoresBlankOrgIDs(t *testing.T) {
	// A blank org_id is a row that carries no tenancy, not a second tenant.
	got, ok := orgVault(t, "org-1", "").SoleOrgID()
	if !ok || got != "org-1" {
		t.Fatalf("SoleOrgID = (%q, %v), want (\"org-1\", true) — a blank org_id must not be "+
			"mistaken for a second organization and block the rail forever", got, ok)
	}
}
