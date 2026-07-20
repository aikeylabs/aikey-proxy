package vault

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// managedKeysSchema builds an in-memory managed_virtual_keys_cache. withGroup
// controls whether the oauth-group columns exist (false = older vault, exercises
// GetActiveManagedKeys' legacy fallback).
func newManagedKeysReader(t *testing.T, withGroup bool) *Reader {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	groupCols := ""
	if withGroup {
		// Mirrors the CLI migration (migrations.rs), which adds all five group
		// columns in ONE batch — a vault with oauth_group_id always has
		// my_assignment_override too, so the group-aware query may select both.
		groupCols = ", oauth_group_id TEXT, group_accounts TEXT, group_runtime TEXT, routing_config TEXT, my_assignment_override TEXT"
	}
	if _, err := db.Exec(`CREATE TABLE managed_virtual_keys_cache (
		virtual_key_id TEXT PRIMARY KEY, alias TEXT NOT NULL, local_alias TEXT,
		provider_code TEXT, protocol_type TEXT, base_url TEXT,
		provider_key_nonce BLOB, provider_key_ciphertext BLOB, provider_base_urls TEXT,
		org_id TEXT, seat_id TEXT, credential_id TEXT, credential_revision TEXT,
		virtual_key_revision TEXT, owner_account_id TEXT,
		key_status TEXT, local_state TEXT` + groupCols + `)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return &Reader{db: db, derivedKey: key}
}

func insertDirectBind(t *testing.T, r *Reader, vkID, plaintext string) {
	t.Helper()
	nonce, ct, err := Encrypt(r.derivedKey, []byte(plaintext))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := r.db.Exec(`INSERT INTO managed_virtual_keys_cache
		(virtual_key_id, alias, provider_code, protocol_type, base_url,
		 provider_key_nonce, provider_key_ciphertext, org_id, seat_id,
		 credential_id, credential_revision, virtual_key_revision, owner_account_id, key_status)
		VALUES (?, ?, 'anthropic', 'anthropic', 'https://x', ?, ?, 'org', 'seat', 'cred', 'r', 'vr', 'acct', 'active')`,
		vkID, vkID, nonce, ct); err != nil {
		t.Fatalf("insert direct-bind: %v", err)
	}
}

func TestGetActiveManagedKeys_GroupAndDirectCoexist(t *testing.T) {
	r := newManagedKeysReader(t, true)
	insertDirectBind(t, r, "vk-direct", "sk-real-key")
	// A group VK: NO provider_key_ciphertext; material is in group_runtime.
	if _, err := r.db.Exec(`INSERT INTO managed_virtual_keys_cache
		(virtual_key_id, alias, provider_code, protocol_type, base_url, org_id, seat_id,
		 credential_id, credential_revision, virtual_key_revision, owner_account_id, key_status,
		 oauth_group_id, group_accounts, group_runtime, routing_config)
		VALUES ('vk-group', 'vk-group', 'anthropic', 'anthropic', '', 'org', 'seat-g',
		 '', '', 'vr', 'acct', 'active',
		 'grp-1', '[{"account_id":"a1"}]', '{"a1":{"access_token":"enc:x"}}', '{"warn_ratio":2}')`); err != nil {
		t.Fatalf("insert group VK: %v", err)
	}

	keys, err := r.GetActiveManagedKeys()
	if err != nil {
		t.Fatalf("GetActiveManagedKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys (direct + group), got %d: %+v", len(keys), keys)
	}
	byID := map[string]ManagedKey{}
	for _, k := range keys {
		byID[k.VirtualKeyID] = k
	}
	d := byID["vk-direct"]
	if d.OauthGroupID != "" || d.PlaintextKey != "sk-real-key" {
		t.Fatalf("direct-bind wrong: oauth_group=%q plaintext=%q", d.OauthGroupID, d.PlaintextKey)
	}
	g := byID["vk-group"]
	if g.OauthGroupID != "grp-1" {
		t.Fatalf("group oauth_group_id not read: %q", g.OauthGroupID)
	}
	if g.PlaintextKey != "" {
		t.Fatalf("group VK must have EMPTY PlaintextKey (material in group_runtime): %q", g.PlaintextKey)
	}
	if g.GroupAccounts == "" || g.GroupRuntime == "" || g.RoutingConfig != `{"warn_ratio":2}` {
		t.Fatalf("group fields not read: %+v", g)
	}
}

func TestGetActiveManagedKeys_LegacyVaultFallback(t *testing.T) {
	// A vault WITHOUT the oauth-group columns: the group-aware query errors and
	// GetActiveManagedKeys must fall back to the legacy query (never lose keys).
	r := newManagedKeysReader(t, false)
	insertDirectBind(t, r, "vk-direct", "sk-real-key")

	keys, err := r.GetActiveManagedKeys()
	if err != nil {
		t.Fatalf("GetActiveManagedKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].VirtualKeyID != "vk-direct" || keys[0].PlaintextKey != "sk-real-key" {
		t.Fatalf("legacy fallback failed to return direct-bind key: %+v", keys)
	}
	if keys[0].OauthGroupID != "" {
		t.Fatalf("legacy vault must yield empty group fields: %q", keys[0].OauthGroupID)
	}
}

// 🔴 P1e (design D-11) PROXY CAPABILITY FENCE: one VK carries TWO bindings, each
// with its own credential, on the composite-PK cache. Routing must select the
// binding matching the request's resolved upstream provider and decrypt THAT
// binding's own key — so "GLM(zhipu key)" and "official(anthropic key)" on one
// VK each reach their own upstream. If GetTeamKeyByID ever ignores the target
// provider (pre-P1e first-row-wins), this goes red.
func TestGetTeamKeyByID_MultiBindingSelectsByProvider(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	// Composite-PK cache (the P1e grain: one row per binding).
	if _, err := db.Exec(`CREATE TABLE managed_virtual_keys_cache (
		virtual_key_id TEXT NOT NULL, alias TEXT NOT NULL, local_alias TEXT,
		provider_code TEXT NOT NULL DEFAULT '', protocol_type TEXT NOT NULL DEFAULT 'openai_compatible',
		base_url TEXT, provider_key_nonce BLOB, provider_key_ciphertext BLOB, provider_base_urls TEXT,
		org_id TEXT, seat_id TEXT, credential_id TEXT, credential_revision TEXT,
		virtual_key_revision TEXT, owner_account_id TEXT, key_status TEXT, local_state TEXT,
		PRIMARY KEY (virtual_key_id, protocol_type, provider_code))`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	r := &Reader{db: db, derivedKey: key}
	insert := func(prov, base, plaintext string) {
		nonce, ct, encErr := Encrypt(r.derivedKey, []byte(plaintext))
		if encErr != nil {
			t.Fatalf("encrypt: %v", encErr)
		}
		if _, err := db.Exec(`INSERT INTO managed_virtual_keys_cache
			(virtual_key_id, alias, provider_code, protocol_type, base_url,
			 provider_key_nonce, provider_key_ciphertext, org_id, seat_id,
			 credential_id, credential_revision, virtual_key_revision, owner_account_id, key_status)
			VALUES ('vk-dual', 'dual', ?, 'anthropic', ?, ?, ?, 'org', 'seat', 'cred', 'r', 'vr', 'acct', 'active')`,
			prov, base, nonce, ct); err != nil {
			t.Fatalf("insert %s binding: %v", prov, err)
		}
	}
	insert("zhipu", "https://open.bigmodel.cn/api/anthropic", "sk-glm-key")
	insert("anthropic", "https://api.anthropic.com", "sk-official-key")

	// Each provider selects ITS OWN binding's key + base_url.
	glm, err := r.GetTeamKeyByID("vk-dual", "zhipu")
	if err != nil || glm == nil {
		t.Fatalf("GetTeamKeyByID(zhipu): %v / %v", glm, err)
	}
	if glm.PlaintextKey != "sk-glm-key" || glm.ProviderCode != "zhipu" {
		t.Errorf("zhipu binding wrong: key=%q provider=%q", glm.PlaintextKey, glm.ProviderCode)
	}
	official, err := r.GetTeamKeyByID("vk-dual", "anthropic")
	if err != nil || official == nil {
		t.Fatalf("GetTeamKeyByID(anthropic): %v / %v", official, err)
	}
	if official.PlaintextKey != "sk-official-key" || official.ProviderCode != "anthropic" {
		t.Errorf("anthropic binding wrong: key=%q provider=%q", official.PlaintextKey, official.ProviderCode)
	}
	// Empty target → deterministic primary (stable provider_code order: anthropic < zhipu).
	primary, err := r.GetTeamKeyByID("vk-dual", "")
	if err != nil || primary == nil {
		t.Fatalf("GetTeamKeyByID(primary): %v / %v", primary, err)
	}
	if primary.ProviderCode != "anthropic" {
		t.Errorf("empty target must resolve a deterministic primary, got provider=%q", primary.ProviderCode)
	}
}
