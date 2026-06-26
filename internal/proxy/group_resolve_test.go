package proxy

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/seatassign"
)

func grKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i*3 + 1)
	}
	return k
}

// encMat encrypts a secret into the at-rest group_runtime shape for tests.
func encMat(t *testing.T, key []byte, m vkeys.GroupRuntimeAccount, secret string) vkeys.GroupRuntimeAccount {
	t.Helper()
	nonce, ct, err := vault.Encrypt(key, []byte(secret))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	m.SecretNonce = base64.StdEncoding.EncodeToString(nonce)
	m.SecretCiphertext = base64.StdEncoding.EncodeToString(ct)
	return m
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// rankOrder returns the seatassign order the resolver must follow (so tests
// pin behaviour to the same lib master uses, not a guessed order).
func rankOrder(seatID string, ids ...string) []string {
	accts := make([]seatassign.Account, len(ids))
	for i, id := range ids {
		accts[i] = seatassign.Account{AccountID: id}
	}
	ordered := seatassign.Rank(seatID, accts)
	out := make([]string, len(ordered))
	for i, a := range ordered {
		out[i] = a.AccountID
	}
	return out
}

func TestResolveGroup_OAuthPrimaryDecrypts(t *testing.T) {
	key := grKey()
	seat := "seat-77"
	order := rankOrder(seat, "acc-a", "acc-b")
	primary := order[0]

	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-a", Identity: "a@x", ProviderCode: "anthropic"},
		{AccountID: "acc-b", Identity: "b@x", ProviderCode: "anthropic"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-a": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-a"}, "tok-a"),
		"acc-b": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-b"}, "tok-b"),
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, OauthGroupID: "grp", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}

	res, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.AccountID != primary {
		t.Fatalf("expected primary %q (seatassign order), got %q", primary, res.AccountID)
	}
	if res.Primary != res.AccountID {
		t.Fatalf("primary usable → no switch: Primary(%q) must equal pick(%q)", res.Primary, res.AccountID)
	}
	if res.CredentialType != "oauth_account" || res.OAuth == nil {
		t.Fatalf("want oauth cred, got %+v", res)
	}
	if res.OAuth.AccessToken != "tok-"+primary[len(primary)-1:] {
		t.Fatalf("decrypted wrong token: %q for %q", res.OAuth.AccessToken, primary)
	}
	if res.OAuth.ExternalID != "uuid-"+primary[len(primary)-1:] {
		t.Fatalf("external_id not carried for Claude metadata: %+v", res.OAuth)
	}
	if res.PlaintextKey != "" {
		t.Fatalf("oauth resolution must not set PlaintextKey")
	}
}

func TestResolveGroup_APIKeyCarriesBaseURL(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-k", ProviderCode: "openai"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-k": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "api_key", BaseURL: "https://up.example", Revision: "r3"}, "sk-secret"),
	}
	route := &vkeys.ResolvedRoute{SeatID: "s1", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}

	res, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.CredentialType != "api_key" || res.PlaintextKey != "sk-secret" {
		t.Fatalf("want api_key secret, got %+v", res)
	}
	if res.BaseURL != "https://up.example" || res.Revision != "r3" {
		t.Fatalf("api_key meta not carried: %+v", res)
	}
	if res.OAuth != nil {
		t.Fatalf("api_key resolution must not set OAuth")
	}
}

func TestResolveGroup_ExpiredPrimaryFallsToNext(t *testing.T) {
	key := grKey()
	seat := "seat-42"
	order := rankOrder(seat, "acc-a", "acc-b")
	primary, secondary := order[0], order[1]

	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-a", ProviderCode: "anthropic"},
		{AccountID: "acc-b", ProviderCode: "anthropic"},
	}
	now := int64(1_000_000)
	mat := map[string]vkeys.GroupRuntimeAccount{
		primary:   encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: now - 1}, "tok-primary"),        // expired
		secondary: encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: now + 10_000}, "tok-secondary"), // fresh
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}

	res, err := resolveGroupCredential(route, key, now, nil, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.AccountID != secondary {
		t.Fatalf("expired primary should fall back to %q, got %q", secondary, res.AccountID)
	}
	if res.OAuth.AccessToken != "tok-secondary" {
		t.Fatalf("wrong fallback token: %q", res.OAuth.AccessToken)
	}
}

func TestResolveGroup_ExhaustedWindowSkipped(t *testing.T) {
	key := grKey()
	seat := "seat-9"
	order := rankOrder(seat, "acc-a", "acc-b")
	primary, secondary := order[0], order[1]

	refs := []vkeys.GroupAccountRef{{AccountID: "acc-a"}, {AccountID: "acc-b"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		primary:   encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, WindowStatus: "exhausted"}, "tok-p"),
		secondary: encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, WindowStatus: "active"}, "tok-s"),
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}

	res, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.AccountID != secondary {
		t.Fatalf("exhausted primary should be skipped → %q, got %q", secondary, res.AccountID)
	}
}

func TestResolveGroup_SkipSetAdvances(t *testing.T) {
	key := grKey()
	seat := "seat-3"
	order := rankOrder(seat, "acc-a", "acc-b")
	primary, secondary := order[0], order[1]

	refs := []vkeys.GroupAccountRef{{AccountID: "acc-a"}, {AccountID: "acc-b"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		primary:   encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok-p"),
		secondary: encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok-s"),
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}

	// Caller already tried the primary (e.g. upstream 401) → must advance.
	res, err := resolveGroupCredential(route, key, 1_000_000, map[string]bool{primary: true}, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.AccountID != secondary {
		t.Fatalf("skip set should advance to %q, got %q", secondary, res.AccountID)
	}
	// N9 #8: the rank-0 primary is reported even when skipped, so the caller can
	// audit the switch (primary != actual pick).
	if res.Primary != primary {
		t.Fatalf("Primary must be the rank-0 account %q (for switch audit), got %q", primary, res.Primary)
	}
	if res.Primary == res.AccountID {
		t.Fatal("a skipped primary must differ from the actual pick (switch case)")
	}
}

func TestResolveGroup_ErrorCodes(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-a", ProviderCode: "anthropic"}}

	// No candidates.
	if _, err := resolveGroupCredential(&vkeys.ResolvedRoute{SeatID: "s", GroupAccounts: "", GroupRuntime: "{}"}, key, 1, nil, ""); !isGroupErr(err, groupErrNoCandidates) {
		t.Fatalf("want NO_CANDIDATES, got %v", err)
	}
	// Candidates present but no material delivered.
	if _, err := resolveGroupCredential(&vkeys.ResolvedRoute{SeatID: "s", GroupAccounts: mustJSON(t, refs), GroupRuntime: ""}, key, 1, nil, ""); !isGroupErr(err, groupErrNoMaterial) {
		t.Fatalf("want NO_MATERIAL, got %v", err)
	}
	// Material present but the only candidate is expired → all unusable.
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-a": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 5}, "tok"),
	}
	route := &vkeys.ResolvedRoute{SeatID: "s", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}
	if _, err := resolveGroupCredential(route, key, 1_000_000, nil, ""); !isGroupErr(err, groupErrAllUnusable) {
		t.Fatalf("want ALL_UNUSABLE, got %v", err)
	}
}

func isGroupErr(err error, code string) bool {
	ge, ok := err.(*groupResolveError)
	return ok && ge.Code == code
}
