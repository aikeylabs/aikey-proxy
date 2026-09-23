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

// TestSeedQuotaSig_MatchesPollerSigWhenCLIWroteTheCache — the phantom quota
// reload seen on every Cluster boot (staging .88 / .90, 2026-09-20..22: each
// boot logs `quota master policy changed` + a full reload).
//
// The cache has a SECOND writer: the cluster daemon's `_internal
// cluster_apply` (aikey-cli src/commands_internal/vault_op.rs, "quota: N
// subject(s) cached (full snapshot)") full-replaces quota_rules_cache on
// daemon start — which a deploy restarts together with the proxy, seconds
// before the proxy seeds. It serializes rules/baselines through
// serde_json::Value, and aikey-cli builds serde_json WITHOUT preserve_order, so
// every object comes out with its keys SORTED; the control plane sends them in
// struct order (metric, period, limit_amount, thresholds / pct, action). Same
// policy, different bytes ⇒ the byte-level signature never matched. The rows
// below are exactly those two spellings of one policy (taken from staging's
// wire answer; the CLI form is that answer with sorted keys).
//
// 能红: sign the raw bytes (the pre-fix quotaSubjectsSig) → seed != poller.
func TestSeedQuotaSig_MatchesPollerSigWhenCLIWroteTheCache(t *testing.T) {
	_, db := newQuotaCacheDBT(t)
	fetched := []quota.PolicySubject{
		{
			SubjectID: "46a0e6ab-seat", SubjectKind: "seat",
			Rules:     json.RawMessage(`[{"metric":"tokens","period":"daily","limit_amount":5,"thresholds":[{"pct":90,"action":"hard_block"}]}]`),
			Baselines: json.RawMessage(`[{"metric":"tokens","period":"daily","used":0}]`),
		},
		{
			SubjectID: "c386078e-seat", SubjectKind: "seat",
			Rules:     json.RawMessage(`[{"metric":"usd","period":"monthly","limit_amount":20,"thresholds":[{"pct":90,"action":"warn","notify":true}]}]`),
			Baselines: json.RawMessage(`[{"metric":"usd","period":"monthly","used":1.5}]`),
		},
		{
			SubjectID: "fsdir:624a2488:od-eb0d", SubjectKind: "group",
			Members: []string{"0e6e05a6", "5c8b7302"},
			Rules:   json.RawMessage(`[]`),
		},
	}
	pollerSig, err := quotaSubjectsSig(append([]quota.PolicySubject(nil), fetched...))
	if err != nil {
		t.Fatal(err)
	}

	// What cluster_apply writes (replace_quota_rules_cache): members via
	// serde_json::to_string(Vec<String>), rules/baselines via Value::to_string()
	// with sorted keys; serde prints the u64 20 as "20" and the f64 1.5 as "1.5".
	for _, row := range [][5]any{
		{"46a0e6ab-seat", "seat", nil,
			`[{"limit_amount":5,"metric":"tokens","period":"daily","thresholds":[{"action":"hard_block","pct":90}]}]`,
			`[{"metric":"tokens","period":"daily","used":0}]`},
		{"c386078e-seat", "seat", nil,
			`[{"limit_amount":20,"metric":"usd","period":"monthly","thresholds":[{"action":"warn","notify":true,"pct":90}]}]`,
			`[{"metric":"usd","period":"monthly","used":1.5}]`},
		{"fsdir:624a2488:od-eb0d", "group", `["0e6e05a6","5c8b7302"]`, `[]`, nil},
	} {
		if _, err := db.Exec(`INSERT INTO quota_rules_cache (subject_id, subject_kind, members, rules, baseline) VALUES (?,?,?,?,?)`,
			row[0], row[1], row[2], row[3], row[4]); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := quota.LoadPolicySubjects(db)
	if err != nil {
		t.Fatal(err)
	}
	seedSig, err := quotaSubjectsSig(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if seedSig != pollerSig {
		t.Fatalf("a cache written by cluster_apply (sorted keys) must sign like the same policy off the wire — "+
			"otherwise every Cluster boot re-detects a phantom quota change and reloads.\n poller: %s\n seed:   %s", pollerSig, seedSig)
	}

	// A real change still moves the signal (limit 5 → 6).
	changed := append([]quota.PolicySubject(nil), fetched...)
	changed[0].Rules = json.RawMessage(`[{"metric":"tokens","period":"daily","limit_amount":6,"thresholds":[{"pct":90,"action":"hard_block"}]}]`)
	if s, _ := quotaSubjectsSig(changed); s == seedSig {
		t.Fatal("canonicalisation swallowed a real limit change")
	}
}
