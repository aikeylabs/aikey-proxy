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

// TestResolveGroup_LoginRequiredNoSkip (RW2/D2): the HRW-primary account has no
// material (member hasn't logged into it) while a LATER candidate does — the
// resolver returns LOGIN_REQUIRED for the PRIMARY and does NOT skip to the
// logged-in one (preserving HRW allocation).
func TestResolveGroup_LoginRequiredNoSkip(t *testing.T) {
	key := grKey()
	seat := "seat-77"
	order := rankOrder(seat, "acc-a", "acc-b")
	primary, other := order[0], order[1]

	refs := []vkeys.GroupAccountRef{{AccountID: "acc-a", ProviderCode: "anthropic"}, {AccountID: "acc-b", ProviderCode: "anthropic"}}
	// Primary carries master's explicit needs_login marker; the NON-primary has a token.
	mat := map[string]vkeys.GroupRuntimeAccount{
		primary: {CredentialType: "oauth_account", NeedsLogin: true}, // master: member not logged into the primary
		other:   encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok"),
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, OauthGroupID: "grp", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}

	_, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	ge, ok := err.(*groupResolveError)
	if !ok || ge.Code != groupErrLoginRequired {
		t.Fatalf("want LOGIN_REQUIRED, got %v", err)
	}
	if ge.Account != primary {
		t.Fatalf("D2: must prompt login for the HRW primary %q (not skip to %q); got %q", primary, other, ge.Account)
	}
}

// TestResolveGroup_AbsentMaterialSkips (P1): an account with NO material entry at
// all (channel-③ hasn't pulled it yet — NOT a master needs_login marker) is SKIPPED
// to the next usable candidate, NOT turned into a hard LOGIN_REQUIRED. This is the
// fix that stops a pre-pull race from telling a member to re-login an account that
// is actually fine.
func TestResolveGroup_AbsentMaterialSkips(t *testing.T) {
	key := grKey()
	seat := "seat-77"
	order := rankOrder(seat, "acc-a", "acc-b")
	other := order[1]

	refs := []vkeys.GroupAccountRef{{AccountID: "acc-a", ProviderCode: "anthropic"}, {AccountID: "acc-b", ProviderCode: "anthropic"}}
	// Primary is simply ABSENT from material (not pulled yet); the other is usable.
	mat := map[string]vkeys.GroupRuntimeAccount{
		other: encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok"),
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, OauthGroupID: "grp", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}

	res, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("absent-material primary must SKIP to the usable candidate, not error: %v", err)
	}
	if res.AccountID != other {
		t.Fatalf("expected fallback to the usable account %q, got %q", other, res.AccountID)
	}
}

// TestResolveGroup_LoginRequiredAfterExhausted (RW2): quota fallback still skips
// an exhausted account, but stops at the next account the member hasn't logged
// into (login required), rather than skipping further to a usable one.
func TestResolveGroup_LoginRequiredAfterExhausted(t *testing.T) {
	key := grKey()
	seat := "seat-9"
	order := rankOrder(seat, "x", "y", "z")
	first, second := order[0], order[1]

	refs := []vkeys.GroupAccountRef{{AccountID: "x", ProviderCode: "anthropic"}, {AccountID: "y", ProviderCode: "anthropic"}, {AccountID: "z", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		// rank-0 exhausted → skipped (quota fallback continues).
		first: encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, WindowStatus: "exhausted"}, "tok"),
		// rank-2 has a usable token, but we must NOT reach it.
		order[2]: encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok-z"),
		// rank-1 (second) carries master's needs_login marker → login required, stops here.
		second: {CredentialType: "oauth_account", NeedsLogin: true},
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, OauthGroupID: "grp", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}

	_, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	ge, ok := err.(*groupResolveError)
	if !ok || ge.Code != groupErrLoginRequired {
		t.Fatalf("want LOGIN_REQUIRED after skipping exhausted, got %v", err)
	}
	if ge.Account != second {
		t.Fatalf("should stop at rank-1 %q (skip exhausted rank-0, not jump to usable rank-2); got %q", second, ge.Account)
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
	// Candidates present but no material pulled yet ("" = poll not landed) → NO_MATERIAL
	// (transient, retry helps).
	if _, err := resolveGroupCredential(&vkeys.ResolvedRoute{SeatID: "s", GroupAccounts: mustJSON(t, refs), GroupRuntime: ""}, key, 1, nil, ""); !isGroupErr(err, groupErrNoMaterial) {
		t.Fatalf("want NO_MATERIAL for unpulled material, got %v", err)
	}
	// 2026-06-30: candidates present (STALE snapshot) but material explicitly "{}" —
	// the proxy polled and this seat's group delivered NO accounts (member removed /
	// unbound, or empty group). Must be NO_CANDIDATES ("contact admin, won't self-
	// resolve"), NOT NO_MATERIAL ("still syncing, retry") — retrying never helps a
	// removed member. This is the fix for the "still syncing forever" report.
	if _, err := resolveGroupCredential(&vkeys.ResolvedRoute{SeatID: "s", GroupAccounts: mustJSON(t, refs), GroupRuntime: "{}"}, key, 1, nil, ""); !isGroupErr(err, groupErrNoCandidates) {
		t.Fatalf("want NO_CANDIDATES for pulled-but-empty material, got %v", err)
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
