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
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/routingwire"
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
			WindowMaxUtilPct: &pct, WindowStatus: "active", WindowResetAt: &reset,
			BaseURL:        "http://127.0.0.1:3000/mock-provider/anthropic",
			EgressProxyURL: "socks5://10.0.0.9:1080"}, // per-account egress (§11.7, P7) — member rail
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
	if oa.BaseURL != "http://127.0.0.1:3000/mock-provider/anthropic" || oa.Revision != "" {
		t.Fatalf("oauth routing metadata or KEY-only revision wrong: %+v", oa)
	}
	// Per-account egress (§11.7, P7) must survive the member-rail projection into the
	// vault material so the resolver hands it to accountEgressTransport — without this
	// a per-account egress set in master silently no-ops on personal/team-member proxies.
	if oa.EgressProxyURL != "socks5://10.0.0.9:1080" {
		t.Fatalf("member-rail egress not carried into group_runtime: %q, want socks5://10.0.0.9:1080", oa.EgressProxyURL)
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
	var gotAuth, gotObsReset string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotObsReset = r.Header.Get(observedResetsHeader)
		if r.URL.Path != "/accounts/me/group-runtime" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"groups":[{"oauth_group_id":"grp-1","routing_config":"{}","accounts":[{"account_id":"a1","credential_type":"oauth_account","access_token":"tok","expires_at":9}]}]}`))
	}))
	defer srv.Close()

	groups, body, err := fetchGroupRuntime(context.Background(), srv.URL, "JWT123", map[string]proxy.ObservedWindowResets{"acc-1": {FiveHour: 1750000000, SevenDay: 1750600000}})
	if err != nil || len(groups) != 1 || groups[0].OauthGroupID != "grp-1" || len(groups[0].Accounts) != 1 {
		t.Fatalf("fetch: err=%v groups=%+v", err, groups)
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
	// Path Z: observed resets piggybacked as base64(JSON) on the pull.
	if gotObsReset == "" {
		t.Fatal("observed-resets header not sent")
	}
	raw, decErr := base64.StdEncoding.DecodeString(gotObsReset)
	if decErr != nil {
		t.Fatalf("observed-resets header not base64: %v", decErr)
	}
	var m map[string]proxy.ObservedWindowResets
	if json.Unmarshal(raw, &m) != nil || m["acc-1"].FiveHour != 1750000000 || m["acc-1"].SevenDay != 1750600000 {
		t.Fatalf("observed-resets header payload wrong: %q → %+v", string(raw), m)
	}

	// Non-200 → ok=false (keep last-known). Nil resets → header omitted.
	var gotObs2 string
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotObs2 = r.Header.Get(observedResetsHeader)
		w.WriteHeader(401)
	}))
	defer bad.Close()
	if _, _, err := fetchGroupRuntime(context.Background(), bad.URL, "x", nil); err == nil {
		t.Fatal("401 must yield a non-nil error (keep-last-known + rail failure count)")
	}
	if gotObs2 != "" {
		t.Fatalf("nil observed-resets must omit the header, got %q", gotObs2)
	}
}

func TestWriteGroupRuntimeForGroups_PerVKEncrypted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vault.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE managed_virtual_keys_cache (
		virtual_key_id TEXT PRIMARY KEY, oauth_group_id TEXT, group_runtime TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	// vk-g1 → grp-1, vk-direct → no group.
	db.Exec(`INSERT INTO managed_virtual_keys_cache (virtual_key_id, oauth_group_id) VALUES ('vk-g1','grp-1')`)
	db.Exec(`INSERT INTO managed_virtual_keys_cache (virtual_key_id, oauth_group_id) VALUES ('vk-direct','')`)
	db.Close()

	key := testKey()
	mks := []vault.ManagedKey{
		{VirtualKeyID: "vk-g1", OauthGroupID: "grp-1"},
		{VirtualKeyID: "vk-direct"},
	}
	groups := []grGroup{{OauthGroupID: "grp-1", Accounts: []grAccount{
		{AccountID: "a1", CredentialType: "oauth_account", AccessToken: "tok-1", ExpiresAt: 5},
	}}}

	if err := writeGroupRuntimeForGroups(dbPath, key, mks, groups, nil, nil); err != nil {
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

// TestWriteGroupRuntimeForGroups_ClearsUndeliveredGroupVK: a local group VK whose
// group is NO LONGER in the delivery (its seat was unbound → master stopped
// delivering it) gets its cached token WIPED to "{}" (access gate, defense-in-
// depth), while a still-delivered group VK keeps fresh material.
func TestWriteGroupRuntimeForGroups_ClearsUndeliveredGroupVK(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vault.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE managed_virtual_keys_cache (
		virtual_key_id TEXT PRIMARY KEY, oauth_group_id TEXT, group_runtime TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	// vk-gone (grp-gone) carries a STALE cached token; vk-stay (grp-stay) is still a member.
	db.Exec(`INSERT INTO managed_virtual_keys_cache (virtual_key_id, oauth_group_id, group_runtime)
		VALUES ('vk-gone','grp-gone','{"a-old":{"secret_ciphertext":"stale","secret_nonce":"x"}}')`)
	db.Exec(`INSERT INTO managed_virtual_keys_cache (virtual_key_id, oauth_group_id, group_runtime)
		VALUES ('vk-stay','grp-stay','{"a-old":{}}')`)
	db.Close()

	key := testKey()
	mks := []vault.ManagedKey{
		{VirtualKeyID: "vk-gone", OauthGroupID: "grp-gone"},
		{VirtualKeyID: "vk-stay", OauthGroupID: "grp-stay"},
	}
	// Delivery includes grp-stay ONLY — grp-gone dropped out (seat unbound).
	groups := []grGroup{{OauthGroupID: "grp-stay", Accounts: []grAccount{
		{AccountID: "a1", CredentialType: "oauth_account", AccessToken: "tok-1", ExpiresAt: 5},
	}}}

	if err := writeGroupRuntimeForGroups(dbPath, key, mks, groups, nil, nil); err != nil {
		t.Fatalf("write: %v", err)
	}

	db, _ = sql.Open("sqlite", dbPath)
	defer db.Close()
	// vk-gone: stale token WIPED to "{}".
	var grGone sql.NullString
	db.QueryRow(`SELECT group_runtime FROM managed_virtual_keys_cache WHERE virtual_key_id='vk-gone'`).Scan(&grGone)
	if grGone.String != "{}" {
		t.Fatalf("undelivered group VK token must be wiped to {}, got %q", grGone.String)
	}
	// vk-stay: fresh material delivered (still a member).
	var grStay sql.NullString
	db.QueryRow(`SELECT group_runtime FROM managed_virtual_keys_cache WHERE virtual_key_id='vk-stay'`).Scan(&grStay)
	var m map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(grStay.String), &m); err != nil || decryptSecret(t, key, m["a1"]) != "tok-1" {
		t.Fatalf("still-member group VK must keep fresh material, got %q", grStay.String)
	}
}

// twoCandGroupAccounts is a seat's candidate list JSON (mirrors the CLI-synced
// group_accounts column) with two equal-priority accounts, so seatassign.Rank
// decides the rank-0 default deterministically.
const twoCandGroupAccounts = `[{"account_id":"a1","priority":1},{"account_id":"a2","priority":1}]`

// TestComputeRoutedAccountID_OverrideBeatsRankZero (C2): the routed account = the
// engine override when it still names a candidate, else the seatassign rank-0 pick.
// Asserted RELATIVE to the deterministic default (HRW output isn't hand-predicted):
// picking the OTHER candidate as override MUST flip the result; a non-candidate
// override MUST be ignored (fall back to rank-0). 能红: if computeRoutedAccountID
// ignored the override, the "override flips it" assertion fails.
func TestComputeRoutedAccountID_OverrideBeatsRankZero(t *testing.T) {
	mk := vault.ManagedKey{SeatID: "seat-x", GroupAccounts: twoCandGroupAccounts}

	def := computeRoutedAccountID(mk, nil, nil, nil, 1_000_000) // rank-0, no override, no cooldown
	if def != "a1" && def != "a2" {
		t.Fatalf("rank-0 default must be a candidate, got %q", def)
	}
	other := "a1"
	if def == "a1" {
		other = "a2"
	}
	// Override naming the OTHER candidate must win.
	if got := computeRoutedAccountID(mk, nil, func(string, string) string { return other }, nil, 1_000_000); got != other {
		t.Fatalf("override should route to %q, got %q", other, got)
	}
	// Override naming a NON-candidate must be ignored → rank-0 default.
	if got := computeRoutedAccountID(mk, nil, func(string, string) string { return "ghost" }, nil, 1_000_000); got != def {
		t.Fatalf("non-candidate override must fall back to rank-0 %q, got %q", def, got)
	}
	// No parseable candidates → "".
	if got := computeRoutedAccountID(vault.ManagedKey{SeatID: "s"}, nil, nil, nil, 1_000_000); got != "" {
		t.Fatalf("no candidates → \"\", got %q", got)
	}
}

// CONVERGENCE (2026-07-01): computeRoutedAccountID (the is_current_routed / current_routed
// DISPLAY stamp read by /user/vault + /user/virtual-keys after A2) is now cooldown-aware —
// it takes the SAME skip view the hot-path resolver uses (proxy.CooldownSkipSet), so the
// displayed account MATCHES what the proxy actually forwards to under cooling-driven
// failover. Mirrors proxy.TestResolveGroup_RoutedFollowsOverride_AndCoolingFallsThrough
// (the actual forward side). 能红: drop the `!skip` guards in computeRoutedAccountID → the
// cooled-rank-0 case below reverts to rank-0 and diverges from the hot path → fails.
func TestComputeRoutedAccountID_CoolingAware_MatchesHotPath(t *testing.T) {
	mk := vault.ManagedKey{SeatID: "seat-cool", GroupAccounts: twoCandGroupAccounts}
	def := computeRoutedAccountID(mk, nil, nil, nil, 1_000_000) // rank-0, nothing cooled
	other := "a1"
	if def == "a1" {
		other = "a2"
	}

	// rank-0 (def) COOLED, no override → the stamp moves to the next non-cooled account,
	// exactly like the hot path's ranked-loop fall-through.
	if got := computeRoutedAccountID(mk, nil, nil, map[string]bool{def: true}, 1_000_000); got != other {
		t.Fatalf("cooled rank-0 → stamp must move to next non-cooled %q, got %q", other, got)
	}
	// Override account COOLED → the override is NOT honored; fall through to non-cooled
	// (same gate as the hot path: `override != "" && !skip[override]`).
	if got := computeRoutedAccountID(mk, nil, func(string, string) string { return def }, map[string]bool{def: true}, 1_000_000); got != other {
		t.Fatalf("cooled override must fall through to %q, got %q", other, got)
	}
	// ALL cooled → no current route. The hot path cannot forward, so the
	// display must not invent a nominal account that is not actually usable.
	if got := computeRoutedAccountID(mk, nil, nil, map[string]bool{"a1": true, "a2": true}, 1_000_000); got != "" {
		t.Fatalf("all cooled → no current route, got %q", got)
	}
}

// TestWriteGroupRuntimeForGroups_StampsCurrentRouted (C2): the writer flags exactly
// ONE account per VK as IsCurrentRouted, honoring the override, and the same group's
// two seats get DIFFERENT routed accounts (per-VK, not per-group-shared).
func TestWriteGroupRuntimeForGroups_StampsCurrentRouted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vault.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE managed_virtual_keys_cache (
		virtual_key_id TEXT PRIMARY KEY, oauth_group_id TEXT, group_runtime TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	db.Exec(`INSERT INTO managed_virtual_keys_cache (virtual_key_id, oauth_group_id) VALUES ('vk-s1','grp-1')`)
	db.Exec(`INSERT INTO managed_virtual_keys_cache (virtual_key_id, oauth_group_id) VALUES ('vk-s2','grp-1')`)
	db.Close()

	key := testKey()
	// Two seats on the SAME group → must get independently-stamped routed accounts.
	mks := []vault.ManagedKey{
		{VirtualKeyID: "vk-s1", OauthGroupID: "grp-1", SeatID: "seat-1", GroupAccounts: twoCandGroupAccounts},
		{VirtualKeyID: "vk-s2", OauthGroupID: "grp-1", SeatID: "seat-2", GroupAccounts: twoCandGroupAccounts},
	}
	groups := []grGroup{{OauthGroupID: "grp-1", Accounts: []grAccount{
		{AccountID: "a1", CredentialType: "oauth_account", AccessToken: "t1", ExpiresAt: 4_000_000_000},
		{AccountID: "a2", CredentialType: "oauth_account", AccessToken: "t2", ExpiresAt: 4_000_000_000},
	}}}
	// Force seat-1 → a1 via override; seat-2 gets no override (rank-0).
	overrideFor := func(seat, _ string) string {
		if seat == "seat-1" {
			return "a1"
		}
		return ""
	}
	if err := writeGroupRuntimeForGroups(dbPath, key, mks, groups, overrideFor, nil); err != nil {
		t.Fatalf("write: %v", err)
	}

	routedOf := func(vk string) string {
		db, _ := sql.Open("sqlite", dbPath)
		defer db.Close()
		var gr string
		db.QueryRow(`SELECT group_runtime FROM managed_virtual_keys_cache WHERE virtual_key_id=?`, vk).Scan(&gr)
		var m map[string]vkeys.GroupRuntimeAccount
		if err := json.Unmarshal([]byte(gr), &m); err != nil {
			t.Fatalf("parse %s: %v", vk, err)
		}
		routed := ""
		for id, a := range m {
			if a.IsCurrentRouted {
				if routed != "" {
					t.Fatalf("%s: more than one account flagged current-routed", vk)
				}
				routed = id
			}
		}
		return routed
	}
	if got := routedOf("vk-s1"); got != "a1" {
		t.Fatalf("seat-1 override → a1 current-routed, got %q", got)
	}
	// seat-2 has no override → rank-0; just assert exactly one is flagged and it's a candidate.
	if got := routedOf("vk-s2"); got != "a1" && got != "a2" {
		t.Fatalf("seat-2 current-routed must be a candidate, got %q", got)
	}
}

// TestStampCurrentRoutedJSON_FlipsFlagInPlace (C2 coupling): the override-change
// re-stamp path moves IsCurrentRouted to the new account WITHOUT touching secrets,
// and reports changed=false when nothing moves.
func TestStampCurrentRoutedJSON_FlipsFlagInPlace(t *testing.T) {
	orig := `{"a1":{"credential_type":"oauth_account","secret_ciphertext":"ZZ","is_current_routed":true},"a2":{"credential_type":"oauth_account","secret_ciphertext":"YY"}}`
	// Re-route to a2.
	out, changed, err := stampCurrentRoutedJSON(orig, "a2")
	if err != nil || !changed {
		t.Fatalf("expected change, got changed=%v err=%v", changed, err)
	}
	var m map[string]vkeys.GroupRuntimeAccount
	json.Unmarshal([]byte(out), &m)
	if m["a1"].IsCurrentRouted || !m["a2"].IsCurrentRouted {
		t.Fatalf("flag should move a1→a2, got a1=%v a2=%v", m["a1"].IsCurrentRouted, m["a2"].IsCurrentRouted)
	}
	// Secret untouched (never decrypted / re-encrypted).
	if m["a1"].SecretCiphertext != "ZZ" || m["a2"].SecretCiphertext != "YY" {
		t.Fatalf("secrets must be untouched, got %q / %q", m["a1"].SecretCiphertext, m["a2"].SecretCiphertext)
	}
	// Idempotent: re-stamping the same routed account reports no change.
	if _, changed2, _ := stampCurrentRoutedJSON(out, "a2"); changed2 {
		t.Fatalf("re-stamp of unchanged routed must report changed=false")
	}
}

func TestStampGroupRuntimeProjection_ProjectsAndClearsCooldownState(t *testing.T) {
	orig := `{"a1":{"credential_type":"oauth_account","secret_ciphertext":"ZZ","is_current_routed":true},"a2":{"credential_type":"oauth_account","secret_ciphertext":"YY"}}`
	resetAt := int64(1_750_003_600)
	out, changed, err := stampGroupRuntimeProjectionJSON(orig, "a2", map[string]proxy.PoolAccountRouteState{
		"a1": {Status: "window_exhausted", RetryAt: resetAt},
	})
	if err != nil || !changed {
		t.Fatalf("project: changed=%v err=%v", changed, err)
	}
	var projected map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(out), &projected); err != nil {
		t.Fatalf("decode projection: %v", err)
	}
	if projected["a1"].RouteStatus != "window_exhausted" || projected["a1"].RouteRetryAt == nil || *projected["a1"].RouteRetryAt != resetAt {
		t.Fatalf("a1 route state missing: %+v", projected["a1"])
	}
	if !projected["a2"].IsCurrentRouted || projected["a1"].IsCurrentRouted {
		t.Fatalf("current route must switch a1→a2: %+v", projected)
	}
	if projected["a1"].SecretCiphertext != "ZZ" {
		t.Fatalf("projection must not alter secrets: %+v", projected["a1"])
	}

	cleared, changed, err := stampGroupRuntimeProjectionJSON(out, "a1", nil)
	if err != nil || !changed {
		t.Fatalf("clear: changed=%v err=%v", changed, err)
	}
	if err := json.Unmarshal([]byte(cleared), &projected); err != nil {
		t.Fatalf("decode cleared projection: %v", err)
	}
	if projected["a1"].RouteStatus != "" || projected["a1"].RouteRetryAt != nil {
		t.Fatalf("expired cooldown projection must clear: %+v", projected["a1"])
	}
}

// Regression fence (2026-07-22): cooldown mutations reach this worker through
// a non-blocking hook. The cooldown-store test fences that producer; this test
// fences the consumer end-to-end through a real vault row, proving one wake-up
// moves the display flag without a material fetch or Proxy reload.
func TestCurrentRoutedRestampWorker_ProjectsWakeup(t *testing.T) {
	dbPath, reader := newOpenableVault(t, []map[string]string{
		{"vk": "vk-route", "seat": "seat-route", "group": "grp-route", "override": ""},
	})

	mk := vault.ManagedKey{
		VirtualKeyID:  "vk-route",
		SeatID:        "seat-route",
		OauthGroupID:  "grp-route",
		GroupAccounts: twoCandGroupAccounts,
	}
	correct := computeRoutedAccountID(mk, nil, nil, nil, 1_000_000)
	wrong := "a1"
	if correct == wrong {
		wrong = "a2"
	}
	runtimeJSON, err := json.Marshal(map[string]vkeys.GroupRuntimeAccount{
		"a1": {CredentialType: "api_key", IsCurrentRouted: wrong == "a1"},
		"a2": {CredentialType: "api_key", IsCurrentRouted: wrong == "a2"},
	})
	if err != nil {
		t.Fatalf("marshal runtime: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open update db: %v", err)
	}
	if _, err := db.Exec(`UPDATE managed_virtual_keys_cache
		SET group_accounts=?, group_runtime=? WHERE virtual_key_id='vk-route'`,
		twoCandGroupAccounts, string(runtimeJSON)); err != nil {
		db.Close()
		t.Fatalf("seed stale current_routed: %v", err)
	}
	db.Close()

	s := newPersistSupervisor(dbPath, reader)
	s.currentRoutedRestampKick = make(chan struct{}, 1)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.currentRoutedRestampLoop()
	}()
	t.Cleanup(func() {
		s.cancel()
		<-done
	})

	s.requestCurrentRoutedRestamp()
	deadline := time.Now().Add(2 * time.Second)
	for {
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatalf("open verify db: %v", err)
		}
		var gotJSON string
		err = db.QueryRow(`SELECT group_runtime FROM managed_virtual_keys_cache
			WHERE virtual_key_id='vk-route'`).Scan(&gotJSON)
		db.Close()
		if err != nil {
			t.Fatalf("read restamped runtime: %v", err)
		}
		var got map[string]vkeys.GroupRuntimeAccount
		if json.Unmarshal([]byte(gotJSON), &got) == nil && got[correct].IsCurrentRouted && !got[wrong].IsCurrentRouted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("wake-up did not move current_routed %s→%s; runtime=%s", wrong, correct, gotJSON)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The material rail and reactive restamp both write the same group_runtime
// column. The material writer must join the projection mutex and capture routing
// state only after it owns that lock; otherwise a slow 60s pull can overwrite a
// newer 429-driven account switch with its stale current_routed flag.
func TestWriteGroupRuntimeSnapshot_SerializesWithReactiveRestamp(t *testing.T) {
	dbPath, reader := newOpenableVault(t, []map[string]string{
		{"vk": "vk-route", "seat": "seat-route", "group": "grp-route", "override": ""},
	})
	s := newPersistSupervisor(dbPath, reader)
	mk := vault.ManagedKey{
		VirtualKeyID:  "vk-route",
		SeatID:        "seat-route",
		OauthGroupID:  "grp-route",
		GroupAccounts: twoCandGroupAccounts,
	}
	groups := []grGroup{{OauthGroupID: "grp-route", Accounts: []grAccount{
		{AccountID: "a1", CredentialType: "oauth_account", AccessToken: "t1", ExpiresAt: time.Now().Add(time.Hour).Unix()},
		{AccountID: "a2", CredentialType: "oauth_account", AccessToken: "t2", ExpiresAt: time.Now().Add(time.Hour).Unix()},
	}}}

	// Hold the same lock a reactive restamp owns. A material writer launched now
	// must not reach SQLite until that restamp has published its latest assignment.
	s.currentRoutedRestampMu.Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- s.writeGroupRuntimeSnapshot(s.active.Load(), []vault.ManagedKey{mk}, groups)
	}()
	<-started
	select {
	case err := <-done:
		s.currentRoutedRestampMu.Unlock()
		t.Fatalf("material writer bypassed projection mutex: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Publish the newest routing truth while the writer is blocked. It must read
	// this value after acquiring the mutex, not retain a pre-lock snapshot.
	s.routingOverrides.StoreRoutes(91, []routingwire.RouteEntry{{
		SeatID: "seat-route", GroupID: "grp-route", AccountID: "a2",
	}})
	s.currentRoutedRestampMu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("write material snapshot: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open verify db: %v", err)
	}
	defer db.Close()
	var gotJSON string
	if err := db.QueryRow(`SELECT group_runtime FROM managed_virtual_keys_cache
		WHERE virtual_key_id='vk-route'`).Scan(&gotJSON); err != nil {
		t.Fatalf("read group_runtime: %v", err)
	}
	var got map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(gotJSON), &got); err != nil {
		t.Fatalf("parse group_runtime: %v", err)
	}
	if !got["a2"].IsCurrentRouted || got["a1"].IsCurrentRouted {
		t.Fatalf("material writer reverted newest route; runtime=%s", gotJSON)
	}
}
