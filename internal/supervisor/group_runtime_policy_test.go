package supervisor

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	_ "modernc.org/sqlite"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 7)
	}
	return k
}

func TestBuildGroupRuntimeJSON_EncryptsBothTypesNoRefresh(t *testing.T) {
	key := testKey()
	pct := 97
	reset := int64(1750000000)
	accts := []grAccount{
		{AccountID: "a-oauth", CredentialType: "oauth_account", AccessToken: "at-live", ExpiresAt: 200,
			WindowMaxUtilPct: &pct, WindowStatus: "active", WindowResetAt: &reset},
		{AccountID: "a-key", CredentialType: "api_key", Key: "sk-real", BaseURL: "https://x", Revision: "r9"},
	}
	js, err := buildGroupRuntimeJSON(key, accts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// No plaintext secret + no refresh anywhere on the wire.
	low := strings.ToLower(js)
	if strings.Contains(js, "at-live") || strings.Contains(js, "sk-real") {
		t.Fatalf("plaintext secret leaked into group_runtime: %s", js)
	}
	if strings.Contains(low, "refresh") {
		t.Fatalf("refresh token reference in group_runtime: %s", js)
	}

	var m map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// OAuth: decrypts back to the access_token + carries window meta.
	oa := m["a-oauth"]
	if got := decryptSecret(t, key, oa); got != "at-live" {
		t.Fatalf("oauth secret decrypt: %q", got)
	}
	if oa.ExpiresAt != 200 || oa.WindowMaxUtilPct == nil || *oa.WindowMaxUtilPct != 97 || oa.WindowStatus != "active" {
		t.Fatalf("oauth meta wrong: %+v", oa)
	}
	if oa.BaseURL != "" || oa.Revision != "" {
		t.Fatalf("oauth must not carry KEY meta: %+v", oa)
	}
	// KEY: decrypts back to the key + carries base_url/revision.
	k := m["a-key"]
	if got := decryptSecret(t, key, k); got != "sk-real" {
		t.Fatalf("key secret decrypt: %q", got)
	}
	if k.BaseURL != "https://x" || k.Revision != "r9" || k.ExpiresAt != 0 {
		t.Fatalf("key meta wrong: %+v", k)
	}
}

func decryptSecret(t *testing.T, key []byte, a vkeys.GroupRuntimeAccount) string {
	t.Helper()
	nonce, err := base64.StdEncoding.DecodeString(a.SecretNonce)
	if err != nil {
		t.Fatalf("nonce b64: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(a.SecretCiphertext)
	if err != nil {
		t.Fatalf("ct b64: %v", err)
	}
	pt, err := vault.Decrypt(key, nonce, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return string(pt)
}

func TestFetchGroupRuntime_ParsesAndSendsBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/accounts/me/group-runtime" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"groups":[{"seat_group_id":"grp-1","routing_config":"{}","accounts":[{"account_id":"a1","credential_type":"oauth_account","access_token":"tok","expires_at":9}]}]}`))
	}))
	defer srv.Close()

	groups, body, ok := fetchGroupRuntime(context.Background(), srv.URL, "JWT123")
	if !ok || len(groups) != 1 || groups[0].SeatGroupID != "grp-1" || len(groups[0].Accounts) != 1 {
		t.Fatalf("fetch: ok=%v groups=%+v", ok, groups)
	}
	if body == "" || !strings.Contains(body, "grp-1") {
		t.Fatalf("raw body (change signature) missing: %q", body)
	}
	if groups[0].Accounts[0].AccessToken != "tok" {
		t.Fatalf("account material not parsed: %+v", groups[0].Accounts[0])
	}
	if gotAuth != "Bearer JWT123" {
		t.Fatalf("bearer not sent: %q", gotAuth)
	}

	// Non-200 → ok=false (keep last-known).
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }))
	defer bad.Close()
	if _, _, ok := fetchGroupRuntime(context.Background(), bad.URL, "x"); ok {
		t.Fatal("401 must yield ok=false")
	}
}

func TestWriteGroupRuntimeForGroups_PerVKEncrypted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vault.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE managed_virtual_keys_cache (
		virtual_key_id TEXT PRIMARY KEY, seat_group_id TEXT, group_runtime TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	// vk-g1 → grp-1, vk-direct → no group.
	db.Exec(`INSERT INTO managed_virtual_keys_cache (virtual_key_id, seat_group_id) VALUES ('vk-g1','grp-1')`)
	db.Exec(`INSERT INTO managed_virtual_keys_cache (virtual_key_id, seat_group_id) VALUES ('vk-direct','')`)
	db.Close()

	key := testKey()
	mks := []vault.ManagedKey{
		{VirtualKeyID: "vk-g1", SeatGroupID: "grp-1"},
		{VirtualKeyID: "vk-direct"},
	}
	groups := []grGroup{{SeatGroupID: "grp-1", Accounts: []grAccount{
		{AccountID: "a1", CredentialType: "oauth_account", AccessToken: "tok-1", ExpiresAt: 5},
	}}}

	if err := writeGroupRuntimeForGroups(dbPath, key, mks, groups); err != nil {
		t.Fatalf("write: %v", err)
	}

	// vk-g1 got an encrypted group_runtime decrypting to tok-1; vk-direct untouched.
	db, _ = sql.Open("sqlite", dbPath)
	defer db.Close()
	var gr sql.NullString
	db.QueryRow(`SELECT group_runtime FROM managed_virtual_keys_cache WHERE virtual_key_id='vk-g1'`).Scan(&gr)
	if !gr.Valid || gr.String == "" {
		t.Fatal("vk-g1 group_runtime not written")
	}
	var m map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(gr.String), &m); err != nil {
		t.Fatalf("parse stored: %v", err)
	}
	if got := decryptSecret(t, key, m["a1"]); got != "tok-1" {
		t.Fatalf("stored secret decrypt: %q", got)
	}

	var grD sql.NullString
	db.QueryRow(`SELECT group_runtime FROM managed_virtual_keys_cache WHERE virtual_key_id='vk-direct'`).Scan(&grD)
	if grD.Valid && grD.String != "" {
		t.Fatalf("direct-bind VK group_runtime must stay empty, got %q", grD.String)
	}
}
