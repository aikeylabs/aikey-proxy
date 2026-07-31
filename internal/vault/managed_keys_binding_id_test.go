package vault

// managed_keys_binding_id_test.go — the fence for reading binding_id WITHOUT
// putting the chain at risk (2026-07-31).
//
// 🔴 The hazard this guards is not "binding_id is missing" — it is what a naive
// fix would have done. GetActiveManagedKeys degrades chain → group → legacy by
// retrying the whole query. Appending binding_id to the CHAIN column list would
// mean a vault that has priority/fallback_role/route_group_id but NOT binding_id
// fails the chain query and silently falls through to the GROUP tier, which
// projects literals: priority 1, role "primary", no group. Every configured
// chain would collapse to a single hop — failover disabled mid-rolling-upgrade,
// with nothing logged, to gain one identifier.
//
// So binding_id is probed on its own. These tests pin both halves: it is read
// when present, and its ABSENCE costs the chain nothing.

import (
	"database/sql"
	"testing"
)

// chainVault builds a cache carrying the chain columns, with binding_id present
// or not — the two states a rolling upgrade actually produces.
func chainVault(t *testing.T, withBindingID bool) *Reader {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	bindingCol := ""
	if withBindingID {
		bindingCol = ", binding_id TEXT NOT NULL DEFAULT ''"
	}
	if _, err := db.Exec(`CREATE TABLE managed_virtual_keys_cache (
		virtual_key_id TEXT, alias TEXT NOT NULL, local_alias TEXT,
		provider_code TEXT, protocol_type TEXT, base_url TEXT,
		provider_key_nonce BLOB, provider_key_ciphertext BLOB, provider_base_urls TEXT,
		org_id TEXT, seat_id TEXT, credential_id TEXT, credential_revision TEXT,
		virtual_key_revision TEXT, owner_account_id TEXT,
		key_status TEXT, local_state TEXT,
		-- The group columns land in alpha.3, before the chain columns in alpha.5,
		-- so every vault that has a chain also has these. GetActiveManagedKeys has
		-- no chain-without-group tier, and a fixture missing them would silently
		-- exercise the legacy path instead of the one under test.
		oauth_group_id TEXT, group_accounts TEXT, group_runtime TEXT,
		routing_config TEXT, my_assignment_override TEXT,
		priority INTEGER NOT NULL DEFAULT 1,
		fallback_role TEXT NOT NULL DEFAULT 'primary',
		route_group_id TEXT NOT NULL DEFAULT '',
		route_group_name TEXT NOT NULL DEFAULT ''` + bindingCol + `)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	r := &Reader{db: db, derivedKey: key}

	nonce, ct, err := Encrypt(r.derivedKey, []byte("sk-test"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cols := `(virtual_key_id, alias, provider_code, protocol_type, base_url,
	          provider_key_nonce, provider_key_ciphertext, org_id, seat_id,
	          credential_id, credential_revision, virtual_key_revision,
	          owner_account_id, key_status, priority, fallback_role,
	          route_group_id, route_group_name`
	vals := `(?, 'vk', 'anthropic', 'anthropic', 'https://x', ?, ?, 'org', 'seat',
	          'cred', 'r', 'vr', 'acct', 'active', 2, 'fallback', 'rg-1', 'main'`
	args := []any{"vk-1", nonce, ct}
	if withBindingID {
		cols += ", binding_id"
		vals += ", ?"
		args = append(args, "b-42")
	}
	if _, err := r.db.Exec(`INSERT INTO managed_virtual_keys_cache `+cols+`) VALUES `+vals+`)`, args...); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return r
}

func TestManagedKeys_BindingIDIsReadWhenTheColumnExists(t *testing.T) {
	keys, err := chainVault(t, true).GetActiveManagedKeys()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].BindingID != "b-42" {
		t.Errorf("BindingID = %q, want \"b-42\" — while this was empty, cooldown and "+
			"stickiness keyed on nothing and the fallback event reported no hop identity",
			keys[0].BindingID)
	}
}

// 🔴 The one that matters: an un-migrated vault must keep its chain.
func TestManagedKeys_MissingBindingIDColumnCostsNothingElse(t *testing.T) {
	keys, err := chainVault(t, false).GetActiveManagedKeys()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	k := keys[0]
	if k.BindingID != "" {
		t.Errorf("BindingID = %q, want empty — absent must read as unknown, never invented", k.BindingID)
	}
	// If binding_id were folded into the chain tier, this query would have fallen
	// through to the GROUP tier and every assertion below would read the
	// pre-upgrade literals instead of the administrator's configuration.
	if k.Priority != 2 {
		t.Errorf("Priority = %d, want 2 — the chain was lost. A vault without binding_id fell "+
			"through to the group tier, which projects priority 1 / 'primary' / no group: "+
			"every configured chain silently collapses to a single hop and failover stops.",
			k.Priority)
	}
	if k.FallbackRole != "fallback" || k.RouteGroupID != "rg-1" || k.RouteGroupName != "main" {
		t.Errorf("chain lost: role=%q group=%q/%q, want fallback / rg-1 / main",
			k.FallbackRole, k.RouteGroupID, k.RouteGroupName)
	}
}
