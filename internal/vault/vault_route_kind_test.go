package vault

// vault_route_kind_test.go — hop ④ of the `route_kind` relay chain: reading the
// node vault's `managed_virtual_keys_cache.route_kind` column into
// ManagedKey.RouteKind.
//
// Why this fence exists at all. `route_kind` travels six hand-copied hops
// (control plane delivery bundle → cluster daemon wire struct → daemon cache
// entry → node vault column → route assembly → worker). A dropped hop is not an
// error, it is an empty string, and an empty string means the worker treats a
// DEVICE-ROUTING token as an ordinary seat token: it would pick an account by
// itself instead of serving the one the control plane bound to that device.
// Design: roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/design.md §4b.7
// Spec: R-device-routing-token-dispatch-20 (worker must refuse when the local
// route's kind is missing — see .S2).
//
// 🔴 Why the column is probed on its own, NOT folded into the chain tier.
// GetActiveManagedKeys degrades chain → group → legacy by RETRYING the whole
// query. Appending route_kind to the chain column list would mean a vault that
// has priority/fallback_role/route_group_*/binding_id but NOT route_kind fails
// the chain query and silently falls through to the GROUP tier, which projects
// literals (priority 1, role "primary", no group, no binding id). Every
// configured fallback chain would collapse to a single hop — failover switched
// off mid-rolling-upgrade — to gain one classifier. Exactly the hazard already
// written down for binding_id in managed_keys_binding_id_test.go. So both
// halves are pinned here: the value is read when the column is there, and its
// ABSENCE costs the chain nothing.
//
// Why an inline CREATE TABLE rather than the real migration chain: the state
// under test is "an older vault that has not run the CLI migration yet", and
// the real chain (aikey-cli/src/migrations.rs) by definition always produces
// the column. The absent-column state is unreachable through it. Same reason
// managed_keys_binding_id_test.go and managed_keys_group_test.go build their
// fixtures this way.

import (
	"database/sql"
	"testing"
)

// routeKindVault builds a cache carrying the chain columns AND binding_id, with
// route_kind present or not — the two states a rolling upgrade actually
// produces (route_kind lands after binding_id, so a vault with route_kind
// always has binding_id, never the other way round).
func routeKindVault(t *testing.T, withRouteKind bool) *Reader {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	routeKindCol := ""
	if withRouteKind {
		routeKindCol = ", route_kind TEXT NOT NULL DEFAULT ''"
	}
	if _, err := db.Exec(`CREATE TABLE managed_virtual_keys_cache (
		virtual_key_id TEXT, alias TEXT NOT NULL, local_alias TEXT,
		provider_code TEXT, protocol_type TEXT, base_url TEXT,
		provider_key_nonce BLOB, provider_key_ciphertext BLOB, provider_base_urls TEXT,
		org_id TEXT, seat_id TEXT, credential_id TEXT, credential_revision TEXT,
		virtual_key_revision TEXT, owner_account_id TEXT,
		key_status TEXT, local_state TEXT,
		oauth_group_id TEXT, group_accounts TEXT, group_runtime TEXT,
		routing_config TEXT, my_assignment_override TEXT,
		priority INTEGER NOT NULL DEFAULT 1,
		fallback_role TEXT NOT NULL DEFAULT 'primary',
		route_group_id TEXT NOT NULL DEFAULT '',
		route_group_name TEXT NOT NULL DEFAULT '',
		binding_id TEXT NOT NULL DEFAULT ''` + routeKindCol + `)`); err != nil {
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
	          route_group_id, route_group_name, binding_id`
	vals := `(?, 'vk', 'anthropic', 'anthropic', 'https://x', ?, ?, 'org', 'seat',
	          'cred', 'r', 'vr', 'acct', 'active', 2, 'fallback', 'rg-1', 'main', 'b-42'`
	args := []any{"vk-1", nonce, ct}
	if withRouteKind {
		cols += ", route_kind"
		vals += ", ?"
		args = append(args, "device_routing_token")
	}
	if _, err := r.db.Exec(`INSERT INTO managed_virtual_keys_cache `+cols+`) VALUES `+vals+`)`, args...); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return r
}

// TestVault_RouteKindColumnOptional pins hop ④ in both directions: read when
// present, empty (never invented, never fatal) when the column is absent, and
// in the absent case nothing else about the row degrades.
func TestVault_RouteKindColumnOptional(t *testing.T) {
	t.Run("read when the column exists", func(t *testing.T) {
		keys, err := routeKindVault(t, true).GetActiveManagedKeys()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(keys))
		}
		if keys[0].RouteKind != "device_routing_token" {
			t.Errorf("RouteKind = %q, want \"device_routing_token\" — while this is empty the "+
				"worker cannot tell a device-routing token from a seat token and picks an "+
				"account by itself (R-device-routing-token-dispatch-20)", keys[0].RouteKind)
		}
	})

	// 🔴 The one that matters: an un-migrated vault must not error, and must keep
	// everything it had.
	t.Run("absent column reads empty and costs nothing else", func(t *testing.T) {
		keys, err := routeKindVault(t, false).GetActiveManagedKeys()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("got %d keys, want 1 — a missing route_kind column must never make keys disappear", len(keys))
		}
		k := keys[0]
		if k.RouteKind != "" {
			t.Errorf("RouteKind = %q, want empty — absent must read as unknown, never invented", k.RouteKind)
		}
		// If route_kind were folded into the chain tier, this query would have
		// fallen through to the GROUP tier and every assertion below would read
		// the pre-upgrade literals instead of the administrator's configuration.
		if k.Priority != 2 {
			t.Errorf("Priority = %d, want 2 — the chain was lost. A vault without route_kind fell "+
				"through to the group tier, which projects priority 1 / 'primary' / no group: "+
				"every configured chain silently collapses to a single hop and failover stops.",
				k.Priority)
		}
		if k.FallbackRole != "fallback" || k.RouteGroupID != "rg-1" || k.RouteGroupName != "main" {
			t.Errorf("chain lost: role=%q group=%q/%q, want fallback / rg-1 / main",
				k.FallbackRole, k.RouteGroupID, k.RouteGroupName)
		}
		if k.BindingID != "b-42" {
			t.Errorf("BindingID = %q, want \"b-42\" — the hop identity was lost along with the chain", k.BindingID)
		}
	})
}
