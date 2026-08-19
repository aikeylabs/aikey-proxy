package supervisor

import (
	"encoding/json"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/quota"

	"database/sql"
	_ "modernc.org/sqlite"
)

// Fence for bugfix 20260725-proxy-startup-reload-storm-5s-health-fail (fix ②,
// stateless quota sig seed).
//
// The invariant: the startup baseline the proxy seeds (quotaSubjectsSig over
// quota.LoadPolicySubjects of the cache) MUST byte-match the signal the poller
// computes off a fresh master fetch (quotaSubjectsSig over the fetched
// PolicySubjects). If they ever drift, every boot re-detects a phantom "quota
// changed" and reloads — the exact regression this fix removes. This exercises
// the real WriteSubjects → LoadPolicySubjects round-trip against the real
// quota_rules_cache schema (kept in lockstep with aikey-cli migrations.rs).
func newQuotaCacheDBT(t *testing.T) (string, *sql.DB) {
	t.Helper()
	path := t.TempDir() + "/vault.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE quota_rules_cache (
		subject_id   TEXT PRIMARY KEY,
		subject_kind TEXT NOT NULL,
		members      TEXT,
		rules        TEXT NOT NULL DEFAULT '[]',
		baseline     TEXT,
		synced_at    INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	return path, db
}

func TestSeedQuotaSig_MatchesPollerSig(t *testing.T) {
	path, db := newQuotaCacheDBT(t)

	// Representative subjects: a seat with rules+baselines, and a group with
	// members and rules — the shapes the poller signs off /v1/quota/policy.
	fetched := []quota.PolicySubject{
		{
			SubjectID:   "seat-a",
			SubjectKind: "seat",
			Rules:       json.RawMessage(`[{"metric":"tokens","period":"daily","limit_amount":100,"thresholds":[{"pct":100,"action":"hard_block"}]}]`),
			Baselines:   json.RawMessage(`[{"metric":"tokens","period":"daily","used":42}]`),
		},
		{
			SubjectID:   "group-x",
			SubjectKind: "group",
			Members:     []string{"seat-a", "seat-b"},
			Rules:       json.RawMessage(`[{"metric":"requests","period":"monthly","limit_amount":5000}]`),
		},
	}

	// The poller signs the fetched wire form (quotaSubjectsSig sorts in place).
	pollerSig, err := quotaSubjectsSig(append([]quota.PolicySubject(nil), fetched...))
	if err != nil {
		t.Fatalf("poller sig: %v", err)
	}

	// The proxy persists them, then on the NEXT boot seeds the baseline from the
	// cache — via the exact path Supervisor.seedQuotaSig uses.
	if err = quota.WriteSubjects(path, fetched); err != nil {
		t.Fatalf("WriteSubjects: %v", err)
	}
	loaded, err := quota.LoadPolicySubjects(db)
	if err != nil {
		t.Fatalf("LoadPolicySubjects: %v", err)
	}
	seedSig, err := quotaSubjectsSig(loaded)
	if err != nil {
		t.Fatalf("seed sig: %v", err)
	}

	if seedSig != pollerSig {
		t.Fatalf("seed sig != poller sig — the first boot poll would false-fire a reload.\n poller: %s\n seed:   %s", pollerSig, seedSig)
	}
}

// quotaSubjectsSig must be order-independent (it sorts by SubjectID) so a
// master that returns subjects in a different order than the cache round-trip
// still produces an identical signal.
func TestQuotaSubjectsSig_OrderIndependent(t *testing.T) {
	a := []quota.PolicySubject{
		{SubjectID: "b", SubjectKind: "seat", Rules: json.RawMessage(`[]`)},
		{SubjectID: "a", SubjectKind: "seat", Rules: json.RawMessage(`[]`)},
	}
	b := []quota.PolicySubject{
		{SubjectID: "a", SubjectKind: "seat", Rules: json.RawMessage(`[]`)},
		{SubjectID: "b", SubjectKind: "seat", Rules: json.RawMessage(`[]`)},
	}
	sa, err := quotaSubjectsSig(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := quotaSubjectsSig(b)
	if err != nil {
		t.Fatal(err)
	}
	if sa != sb {
		t.Fatalf("sig is order-dependent: %s vs %s", sa, sb)
	}
}
