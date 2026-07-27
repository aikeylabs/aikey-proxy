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
		"acc-a": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-a", EgressProxyURL: "socks5://10.0.0.a:1080"}, "tok-a"),
		"acc-b": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-b", EgressProxyURL: "socks5://10.0.0.b:1080"}, "tok-b"),
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
	// Per-account egress (§11.7, P7): the RESOLVED account's egress_proxy_url must
	// flow onto the resolution so the caller can pin this account's exit IP.
	if want := "socks5://10.0.0." + primary[len(primary)-1:] + ":1080"; res.EgressProxyURL != want {
		t.Fatalf("egress_proxy_url not carried from resolved account: got %q want %q", res.EgressProxyURL, want)
	}
}

func TestResolveGroup_RuntimeOnlyAddedAccountCanServeWithoutKeySync(t *testing.T) {
	key := grKey()
	material := map[string]vkeys.GroupRuntimeAccount{
		"account-2": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account",
			CredentialID:   "credential-2",
			Identity:       "member@example.com",
			ProviderCode:   "anthropic",
			ProtocolType:   "anthropic",
			Priority:       2,
			ExpiresAt:      9_000_000_000,
		}, "token-2"),
	}
	route := &vkeys.ResolvedRoute{
		SeatID:        "seat-existing",
		GroupAccounts: `[{"account_id":"account-1","priority":1,"credential_id":"credential-1"}]`,
		GroupRuntime:  mustJSON(t, material),
	}

	got, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("runtime-only added account should route without key sync: %v", err)
	}
	if got.AccountID != "account-2" || got.CredentialID != "credential-2" || got.OAuth == nil || got.OAuth.AccessToken != "token-2" {
		t.Fatalf("runtime-only account resolution wrong: %+v", got)
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

// A needs-login account discovered after the assigned account became globally
// unavailable is the new routed destination. Resolution must stop on it so the
// display and login page can converge before any later usable account is tried.
func TestResolveGroup_NeedsLoginSuccessorIsActionable(t *testing.T) {
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
	if !ok || ge.Code != groupErrLoginRequired || ge.Account != second {
		t.Fatalf("want LOGIN_REQUIRED for rank-1 successor %q, got %v", second, err)
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

func TestResolveGroup_RuntimeBaseURLOverridesStaticCandidate(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{
		AccountID: "acc-mock", ProviderCode: "mock", ProtocolType: "anthropic",
		BaseURL: "http://127.0.0.1:3000/mock-provider/anthropic",
	}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-mock": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account",
			ProviderCode:   "mock",
			ProtocolType:   "anthropic",
			BaseURL:        "http://host.docker.internal:3000/mock-provider/anthropic",
			ExternalID:     "mock-external-id",
			ExpiresAt:      9_000_000_000,
		}, "mock-token"),
	}
	route := &vkeys.ResolvedRoute{
		SeatID: "seat-1", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}

	res, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.BaseURL != "http://host.docker.internal:3000/mock-provider/anthropic" {
		t.Fatalf("base URL=%q, want consumer-specific runtime rail", res.BaseURL)
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
	// R36 (2026-07-04, codex pools): the only candidate is EXPIRED → LOGIN_REQUIRED,
	// NOT ALL_UNUSABLE. An expired member token is member-fixable (re-login mints a
	// new one; codex tokens live ~10 days so this is their steady-state path), so the
	// resolver prompts a self-serve 401 login for that account instead of dead-ending
	// in the admin-facing 503.
	expMat := map[string]vkeys.GroupRuntimeAccount{
		"acc-a": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 5}, "tok"),
	}
	expRoute := &vkeys.ResolvedRoute{SeatID: "s", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, expMat)}
	if _, err := resolveGroupCredential(expRoute, key, 1_000_000, nil, ""); !isGroupErr(err, groupErrLoginRequired) {
		t.Fatalf("want LOGIN_REQUIRED for the expired-only case (R36), got %v", err)
	}

	// Window-exhausted (NOT expired) is genuinely not member-fixable → ALL_UNUSABLE.
	// Only routing around it (or waiting for the window to reset) helps, so it stays
	// the admin-facing dead-end and does NOT downgrade to a login prompt.
	exhMat := map[string]vkeys.GroupRuntimeAccount{
		"acc-a": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, WindowStatus: "exhausted"}, "tok"),
	}
	exhRoute := &vkeys.ResolvedRoute{SeatID: "s", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, exhMat)}
	if _, err := resolveGroupCredential(exhRoute, key, 1_000_000, nil, ""); !isGroupErr(err, groupErrAllUnusable) {
		t.Fatalf("want ALL_UNUSABLE for the window-exhausted-only case, got %v", err)
	}
}

func isGroupErr(err error, code string) bool {
	ge, ok := err.(*groupResolveError)
	return ok && ge.Code == code
}
