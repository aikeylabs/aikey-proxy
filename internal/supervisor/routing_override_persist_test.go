package supervisor

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/pkg/routingwire"

	_ "modernc.org/sqlite"
)

// newOpenableVault builds a REAL on-disk vault that vault.Open can open (config
// table with salt/kdf/password_hash) plus a managed_virtual_keys_cache in the
// SAME column shape the CLI migration produces (all five group columns land in
// one batch — schema-code coherence). Low Argon2 cost keeps the test fast.
// Returns (dbPath, reader).
func newOpenableVault(t *testing.T, rows []map[string]string) (string, *vault.Reader) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "vault.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE config (key TEXT PRIMARY KEY, value BLOB)`); err != nil {
		t.Fatalf("create config: %v", err)
	}
	salt := []byte("0123456789abcdef")
	u32 := func(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
	// Cheap KDF params (test-only): 8 KiB / 1 iter / 1 lane.
	for k, v := range map[string][]byte{
		"master_salt": salt, "kdf_m_cost": u32(8), "kdf_t_cost": u32(1), "kdf_p_cost": u32(1),
	} {
		if _, err := db.Exec(`INSERT INTO config (key, value) VALUES (?,?)`, k, v); err != nil {
			t.Fatalf("config %s: %v", k, err)
		}
	}
	derived := vault.DeriveKeyWithParams([]byte("pw"), salt, 8, 1, 1)
	if _, err := db.Exec(`INSERT INTO config (key, value) VALUES ('password_hash',?)`, derived); err != nil {
		t.Fatalf("password_hash: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE managed_virtual_keys_cache (
		virtual_key_id TEXT PRIMARY KEY, alias TEXT NOT NULL, local_alias TEXT,
		provider_code TEXT, protocol_type TEXT, base_url TEXT,
		provider_key_nonce BLOB, provider_key_ciphertext BLOB, provider_base_urls TEXT,
		org_id TEXT, seat_id TEXT, credential_id TEXT, credential_revision TEXT,
		virtual_key_revision TEXT, owner_account_id TEXT,
		key_status TEXT, local_state TEXT,
		oauth_group_id TEXT, group_accounts TEXT, group_runtime TEXT,
		routing_config TEXT, my_assignment_override TEXT)`); err != nil {
		t.Fatalf("create mvk: %v", err)
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO managed_virtual_keys_cache
			(virtual_key_id, alias, provider_code, protocol_type, base_url,
			 org_id, seat_id, credential_id, credential_revision, virtual_key_revision,
			 oauth_group_id, my_assignment_override, key_status)
			VALUES (?,?, 'anthropic', 'anthropic', '', 'org', ?, 'cred', 'r', 'vr', ?, ?, 'active')`,
			r["vk"], r["vk"], r["seat"], r["group"], r["override"]); err != nil {
			t.Fatalf("insert %s: %v", r["vk"], err)
		}
	}
	db.Close()

	reader, err := vault.Open(dbPath, "pw")
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	t.Cleanup(func() { reader.Close() })
	return dbPath, reader
}

func newPersistSupervisor(dbPath string, reader *vault.Reader) *Supervisor {
	cfg := &config.Config{}
	cfg.Vault.Path = dbPath
	s := &Supervisor{cfg: cfg, routingOverrides: proxy.NewRoutingOverrideCache()}
	s.active.Store(&generation{vault: reader})
	return s
}

func readOverrideColumn(t *testing.T, dbPath, vk string) string {
	t.Helper()
	db, _ := sql.Open("sqlite", dbPath)
	defer db.Close()
	var v sql.NullString
	if err := db.QueryRow(`SELECT my_assignment_override FROM managed_virtual_keys_cache
		WHERE virtual_key_id=?`, vk).Scan(&v); err != nil {
		t.Fatalf("read %s: %v", vk, err)
	}
	return v.String
}

// The §5.3 restart contract, exercised through the REAL production functions:
// persistAssignmentOverrides writes the applied cache to the columns, then a
// FRESH supervisor (new cache, same vault) hydrates and resolves the same
// (seat,group)→account — including blocked seats (losing that negative
// directive would re-admit a seat the engine capped). 能红: drop the persist
// call, the blocked branch, or hydrate's StoreRoutes and this reds.
func TestPersistThenHydrate_RestartConsistency(t *testing.T) {
	t.Setenv("AIKEY_PROXY_OAUTH_GROUP_ENABLED", "1")
	dbPath, reader := newOpenableVault(t, []map[string]string{
		{"vk": "vk-a", "seat": "seat-1", "group": "grp-1", "override": ""},
		{"vk": "vk-b", "seat": "seat-2", "group": "grp-1", "override": ""},
		{"vk": "vk-c", "seat": "seat-3", "group": "grp-old", "override": ""},
	})

	// Process 1: a live pull stored assignments; persist mirrors them to vault.
	s1 := newPersistSupervisor(dbPath, reader)
	s1.routingOverrides.StoreRoutes(42, []routingwire.RouteEntry{
		{SeatID: "seat-1", GroupID: "grp-1", AccountID: "acc-engine"},
		{SeatID: "seat-2", GroupID: "grp-1", Blocked: true},
		{SeatID: "seat-3", GroupID: "grp-old", Removed: true},
	})
	s1.persistAssignmentOverrides(s1.active.Load(), 42)

	var pa persistedAssignment
	if err := json.Unmarshal([]byte(readOverrideColumn(t, dbPath, "vk-a")), &pa); err != nil {
		t.Fatalf("vk-a column not valid JSON: %v", err)
	}
	if pa.AccountID != "acc-engine" || pa.RoutingVersion != 42 || pa.SyncedAt == 0 {
		t.Fatalf("vk-a persisted payload wrong: %+v", pa)
	}
	var pb persistedAssignment
	if err := json.Unmarshal([]byte(readOverrideColumn(t, dbPath, "vk-b")), &pb); err != nil {
		t.Fatalf("vk-b column not valid JSON: %v", err)
	}
	if !pb.Blocked {
		t.Fatalf("vk-b must persist the blocked directive: %+v", pb)
	}
	var pc persistedAssignment
	if err := json.Unmarshal([]byte(readOverrideColumn(t, dbPath, "vk-c")), &pc); err != nil {
		t.Fatalf("vk-c column not valid JSON: %v", err)
	}
	if !pc.Removed {
		t.Fatalf("vk-c must persist the removal tombstone: %+v", pc)
	}

	// Process 2 (simulated restart): fresh cache, same vault → hydrate.
	s2 := newPersistSupervisor(dbPath, reader)
	s2.hydrateRoutingOverrides(s2.active.Load())

	if got := s2.routingOverrides.Assignment("seat-1", "grp-1"); got != "acc-engine" {
		t.Fatalf("post-restart assignment=%q want acc-engine (hydrate lost it)", got)
	}
	if !s2.routingOverrides.Blocked("seat-2", "grp-1") {
		t.Fatal("post-restart blocked seat lost — engine cap would be re-admitted")
	}
	if !s2.routingOverrides.Removed("seat-3", "grp-old") {
		t.Fatal("post-restart removal tombstone lost — deleted access could be resurrected")
	}
	if v := s2.routingOverrides.Version(); v != 42 {
		t.Fatalf("hydrated version=%d want 42", v)
	}
	if !s2.routingOverrides.Stored() {
		t.Fatal("hydrate must mark Stored (first-pull version-skip contract)")
	}
}

// A withdrawn override must CLEAR the column, and a later hydrate must not
// resurrect it (§5.3 "hydrate can't resurrect a withdrawn assignment").
func TestPersistAssignmentOverrides_ClearsWithdrawn(t *testing.T) {
	t.Setenv("AIKEY_PROXY_OAUTH_GROUP_ENABLED", "1")
	pa, _ := json.Marshal(persistedAssignment{AccountID: "acc-old", RoutingVersion: 41, SyncedAt: 90})
	dbPath, reader := newOpenableVault(t, []map[string]string{
		{"vk": "vk-a", "seat": "seat-1", "group": "grp-1", "override": string(pa)},
	})

	s := newPersistSupervisor(dbPath, reader)
	// Engine now overrides NOTHING (empty route set at a newer version).
	s.routingOverrides.StoreRoutes(50, nil)
	s.persistAssignmentOverrides(s.active.Load(), 50)

	if got := readOverrideColumn(t, dbPath, "vk-a"); got != "" {
		t.Fatalf("withdrawn override must clear the column, still %q", got)
	}
	// Restart: nothing to hydrate → cache stays unstored (local pick default).
	s2 := newPersistSupervisor(dbPath, reader)
	s2.hydrateRoutingOverrides(s2.active.Load())
	if s2.routingOverrides.Stored() {
		t.Fatal("cleared columns must not hydrate a stale assignment")
	}
}

// Corrupt column content is skipped (never fails hydrate), and a healthy row
// alongside it still hydrates.
func TestHydrateRoutingOverrides_SkipsCorruptRow(t *testing.T) {
	t.Setenv("AIKEY_PROXY_OAUTH_GROUP_ENABLED", "1")
	good, _ := json.Marshal(persistedAssignment{AccountID: "acc-ok", RoutingVersion: 7, SyncedAt: 9})
	dbPath, reader := newOpenableVault(t, []map[string]string{
		{"vk": "vk-bad", "seat": "seat-9", "group": "grp-1", "override": "{not-json"},
		{"vk": "vk-good", "seat": "seat-1", "group": "grp-1", "override": string(good)},
	})
	s := newPersistSupervisor(dbPath, reader)
	s.hydrateRoutingOverrides(s.active.Load())
	if got := s.routingOverrides.Assignment("seat-1", "grp-1"); got != "acc-ok" {
		t.Fatalf("healthy row must hydrate despite corrupt sibling, got %q", got)
	}
	if got := s.routingOverrides.Assignment("seat-9", "grp-1"); got != "" {
		t.Fatalf("corrupt row must be skipped, got %q", got)
	}
}

// Steady state writes nothing: persisting the same assignment at the same
// version twice must not churn the vault (synced_at-only diffs are ignored).
func TestPersistAssignmentOverrides_NoChurnOnSteadyState(t *testing.T) {
	t.Setenv("AIKEY_PROXY_OAUTH_GROUP_ENABLED", "1")
	dbPath, reader := newOpenableVault(t, []map[string]string{
		{"vk": "vk-a", "seat": "seat-1", "group": "grp-1", "override": ""},
	})
	s := newPersistSupervisor(dbPath, reader)
	s.routingOverrides.StoreRoutes(42, []routingwire.RouteEntry{
		{SeatID: "seat-1", GroupID: "grp-1", AccountID: "acc-engine"},
	})
	s.persistAssignmentOverrides(s.active.Load(), 42)
	first := readOverrideColumn(t, dbPath, "vk-a")

	s.persistAssignmentOverrides(s.active.Load(), 42)
	second := readOverrideColumn(t, dbPath, "vk-a")
	if first != second {
		t.Fatalf("steady-state persist must be byte-identical (no synced_at churn): %q vs %q", first, second)
	}
}

// sameAssignmentPayload ignores synced_at (a timestamp-only diff is churn) but
// distinguishes account / blocked / version changes.
func TestSameAssignmentPayload(t *testing.T) {
	a := `{"account_id":"x","routing_version":1,"synced_at":100}`
	b := `{"account_id":"x","routing_version":1,"synced_at":999}`
	if !sameAssignmentPayload(a, b) {
		t.Fatal("timestamp-only diff must compare equal (no write churn)")
	}
	c := `{"account_id":"y","routing_version":1,"synced_at":100}`
	if sameAssignmentPayload(a, c) {
		t.Fatal("account change must compare different")
	}
	d := `{"account_id":"x","routing_version":2,"synced_at":100}`
	if sameAssignmentPayload(a, d) {
		t.Fatal("version change must compare different")
	}
	if sameAssignmentPayload("", a) || sameAssignmentPayload(a, "") {
		t.Fatal("empty vs non-empty must compare different (set/clear transitions)")
	}
	if !sameAssignmentPayload("", "") {
		t.Fatal("both empty must compare equal")
	}
	if sameAssignmentPayload("not-json", a) {
		t.Fatal("corrupt existing must trigger a rewrite (repair path)")
	}
}
