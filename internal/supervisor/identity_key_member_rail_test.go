package supervisor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// TestIdentityKey_MemberRailReachesResolvedRoute is the MEMBER-rail half of the
// per-account identity-key chain (Personal / Production: the always-on proxy
// pulls GET /accounts/me/group-runtime itself; on a Cluster node the same
// material arrives through the daemon spine instead — that rail is fenced by
// aikey-test's TestIdentityKey_RidesTheDaemonSpine).
//
// spec: R-codex-identity-rewrite-4 控制面按账号派生专属密钥、随账号材料加密下发
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md
//
// Why the fence spans the WHOLE rail rather than one field (手工搬运的中转层会静
// 默吞字段): the key crosses three hand-copied hops — master's AccountMaterial
// JSON → grAccount → buildGroupRuntimeMap's per-field copy → the at-rest
// vkeys.GroupRuntimeAccount the resolver reads. A forgotten line on any hop is
// an EMPTY value on the node, not an error, and the worker would then silently
// serve every account on its locally derived fallback key.
//
// The two halves of the chain meet at vkeys.GroupRuntimeAccount — the shared
// definition that exists precisely so the writer here and the reader in package
// proxy cannot drift. Go cannot put both halves in one test (package proxy is
// imported BY this package, so its unexported resolver is unreachable here);
// the reader half — material → the resolved route the rewrite consumes, plus
// the missing-key degradation — is
// TestIdentityKey_MissingFallsBackToLocalDerivationAndCRIT in internal/proxy.
func TestIdentityKey_MemberRailReachesResolvedRoute(t *testing.T) {
	// The 32-byte per-account key the control plane derived (HKDF over
	// MASTER_KEY + credential_id) and ships base64'd on the member rail, exactly
	// as the access_token rides it: plaintext over TLS, re-encrypted with the
	// vault key before it touches this machine's disk.
	deliveredKey := bytes.Repeat([]byte{0x3f}, 32)
	deliveredB64 := base64.StdEncoding.EncodeToString(deliveredKey)

	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/accounts/me/group-runtime" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(fmt.Sprintf(
			`{"groups":[{"oauth_group_id":"grp-idk","routing_config":"{}","accounts":[`+
				`{"account_id":"acc-idk","credential_id":"cred-idk","credential_type":"oauth_account",`+
				`"access_token":"at-live","expires_at":9000000000,"identity_key":%q},`+
				`{"account_id":"acc-needs-login","credential_id":"cred-needs-login",`+
				`"credential_type":"oauth_account","needs_login":true,"identity_key":%q}]}]}`,
			deliveredB64, deliveredB64)))
	}))
	defer master.Close()

	// (1) The master wire: the pull must parse identity_key off AccountMaterial.
	groups, _, err := fetchGroupRuntime(context.Background(), master.URL, "JWT", nil)
	if err != nil || len(groups) != 1 || len(groups[0].Accounts) != 2 {
		t.Fatalf("member-rail pull: err=%v groups=%+v", err, groups)
	}
	if got := groups[0].Accounts[0].IdentityKey; got != deliveredB64 {
		t.Fatalf("identity key dropped on the member-rail wire (grAccount): got %d chars, want the delivered %d-char base64", len(got), len(deliveredB64))
	}

	// (2) The vault projection: encrypted with the SAME key and helper the token
	// uses, then read back the way the resolver does.
	key := testKey()
	js, err := buildGroupRuntimeJSON(key, groups[0].Accounts)
	if err != nil {
		t.Fatalf("buildGroupRuntimeJSON: %v", err)
	}
	if strings.Contains(js, deliveredB64) {
		t.Fatalf("the per-account identity key was stored in the CLEAR — it must be AES-GCM encrypted with the vault key like the token: %s", js)
	}
	var material map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(js), &material); err != nil {
		t.Fatalf("unmarshal group_runtime: %v", err)
	}
	account, ok := material["acc-idk"]
	if !ok {
		t.Fatalf("account absent from the projected group_runtime: %s", js)
	}
	if account.IdentityKeyNonce == "" || account.IdentityKeyCiphertext == "" {
		t.Fatalf("identity key dropped by the member-rail relay (buildGroupRuntimeMap) — the worker would fall back to a locally derived key for every account: %+v", account)
	}
	if got := decryptIdentityKey(t, key, account); !bytes.Equal(got, deliveredKey) {
		t.Fatalf("identity key did not survive the vault round-trip: got %d bytes, want the delivered %d", len(got), len(deliveredKey))
	}

	// (3) Account-level, login-independent — same rule as the per-account egress
	// (bugfix 2026-07-17: egress was gated behind the login check and a
	// not-logged-in account silently delivered ""). The key is a property of the
	// ACCOUNT, not of this member's token, so it must be pinned the moment the
	// member logs in.
	pending, ok := material["acc-needs-login"]
	if !ok {
		t.Fatalf("needs-login account absent from the projected group_runtime: %s", js)
	}
	if !pending.NeedsLogin {
		t.Fatalf("needs-login marker lost: %+v", pending)
	}
	if pending.IdentityKeyNonce == "" || pending.IdentityKeyCiphertext == "" {
		t.Fatalf("needs-login account lost its identity key — it is account-level material, not token-level: %+v", pending)
	}
	if got := decryptIdentityKey(t, key, pending); !bytes.Equal(got, deliveredKey) {
		t.Fatalf("needs-login account's identity key did not survive the round-trip: got %d bytes", len(got))
	}
	if pending.SecretNonce != "" || pending.SecretCiphertext != "" {
		t.Fatalf("needs-login account must still carry NO token secret: %+v", pending)
	}
}

// TestIdentityKey_AbsentOnTheWireStaysAbsentAtRest is the negative control for
// the fence above: an older control plane that sends no identity_key must
// produce material with NO identity_key_* fields (so the worker's degradation
// path is what runs) rather than an all-zero or empty-string ciphertext that
// would decrypt to a shared, guessable key.
func TestIdentityKey_AbsentOnTheWireStaysAbsentAtRest(t *testing.T) {
	js, err := buildGroupRuntimeJSON(testKey(), []grAccount{{
		AccountID: "acc-old-master", CredentialID: "cred-old-master",
		CredentialType: "oauth_account", AccessToken: "at-live", ExpiresAt: 9_000_000_000,
	}})
	if err != nil {
		t.Fatalf("buildGroupRuntimeJSON: %v", err)
	}
	if strings.Contains(js, "identity_key") {
		t.Fatalf("an account with no delivered identity key must emit NO identity_key_* fields (omitempty), so old payloads stay byte-unchanged: %s", js)
	}
	var material map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(js), &material); err != nil {
		t.Fatalf("unmarshal group_runtime: %v", err)
	}
	if a := material["acc-old-master"]; a.IdentityKeyNonce != "" || a.IdentityKeyCiphertext != "" {
		t.Fatalf("absent key became present-but-empty material: %+v", a)
	}
}

func decryptIdentityKey(t *testing.T, key []byte, a vkeys.GroupRuntimeAccount) []byte {
	t.Helper()
	nonce, err := base64.StdEncoding.DecodeString(a.IdentityKeyNonce)
	if err != nil {
		t.Fatalf("identity key nonce b64: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(a.IdentityKeyCiphertext)
	if err != nil {
		t.Fatalf("identity key ciphertext b64: %v", err)
	}
	pt, err := vault.Decrypt(key, nonce, ct)
	if err != nil {
		t.Fatalf("identity key decrypt: %v", err)
	}
	return pt
}
