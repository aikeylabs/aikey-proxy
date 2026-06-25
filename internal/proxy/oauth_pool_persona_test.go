package proxy

// NP-1 tests: AccountPersona identity normalization for pooled Claude accounts.
// The security contract: a pool account's traffic must reach Anthropic with ONE
// device / session / OS-arch / UA per account_uuid, regardless of what the real
// client (a Claude Code employee) put on the request — otherwise N employees'
// real fingerprints leak under one account and the account is banned (§3.1).

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestPoolSession_Rolling pins NP-2 rotation: stable while busy, rotates after
// idle TTL, rotates after max age, and N callers on one account share one id.
func TestPoolSession_Rolling(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	store := &poolSessionStore{m: map[string]*rollingSession{}, now: func() time.Time { return now }}

	first := store.sessionID("acct")
	if first == "" {
		t.Fatal("empty session id")
	}
	// Two more employees on the SAME account, same instant → same id (N→1).
	if store.sessionID("acct") != first || store.sessionID("acct") != first {
		t.Fatal("concurrent employees on one account must share one session")
	}
	// Busy: 14 min later (< idle TTL) → still the same session.
	now = now.Add(14 * time.Minute)
	if store.sessionID("acct") != first {
		t.Fatal("session must stay stable within the idle window")
	}
	// Idle: 16 min after the last use → rotate.
	now = now.Add(16 * time.Minute)
	second := store.sessionID("acct")
	if second == first {
		t.Fatal("session must rotate after idle TTL")
	}
	// Max age: keep it busy past poolSessionMaxAge → rotate even without idle.
	cur := second
	for elapsed := time.Duration(0); elapsed <= poolSessionMaxAge+time.Hour; elapsed += 10 * time.Minute {
		now = now.Add(10 * time.Minute)
		if id := store.sessionID("acct"); id != cur {
			cur = id // rotated
		}
	}
	if cur == second {
		t.Fatal("session must rotate after max age even under continuous traffic (防永生)")
	}
	// Different account → independent session.
	if store.sessionID("other") == cur {
		t.Fatal("different accounts must not share a session")
	}
}

func wantDeviceID(accountID string) string {
	h := sha256.Sum256([]byte(accountID))
	return hex.EncodeToString(h[:])
}

func TestApplyPoolPersona_OverridesClientIdentity(t *testing.T) {
	body := `{"model":"claude-sonnet-4-5","metadata":{"user_id":"user_CLIENTDEVICE_account_x_session_CLIENTSESS"},"messages":[]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Client-set identity that MUST be overridden for a pool account:
	req.Header.Set("X-Stainless-OS", "Windows")
	req.Header.Set("X-Stainless-Arch", "x64")
	req.Header.Set("User-Agent", "opencode/1.0 (third-party)")
	req.Header.Set("X-Claude-Code-Session-Id", "client-session-xyz")

	cred := &OAuthCredential{Provider: "anthropic", AccountID: "acct_pool_1", ExternalID: "ext-uuid-1", Pooled: true}
	applyPoolPersona(req, cred)

	// OS/arch/UA overridden to THIS account's pinned persona (per-account, not the
	// client's Windows/x64/third-party UA). Compare against the deterministic pick.
	want := personaForAccount("acct_pool_1")
	if got := req.Header.Get("X-Stainless-OS"); got != want.os {
		t.Fatalf("X-Stainless-OS=%q want %q (per-account persona, override client Windows)", got, want.os)
	}
	if got := req.Header.Get("X-Stainless-Arch"); got != want.arch {
		t.Fatalf("X-Stainless-Arch=%q want %q (override)", got, want.arch)
	}
	if got := req.Header.Get("User-Agent"); got != "claude-cli/"+want.cliVersion+" (external, cli)" {
		t.Fatalf("User-Agent=%q want claude-cli/%s (override third-party UA)", got, want.cliVersion)
	}
	// Whatever the persona, it must NOT be the client's leaked third-party UA.
	if strings.Contains(req.Header.Get("User-Agent"), "opencode") {
		t.Fatalf("client third-party UA leaked: %q", req.Header.Get("User-Agent"))
	}
	// Session normalized (not the client's) — the header + metadata must agree on
	// the same masked session (NP-2 rolling value, so compare to itself).
	sess := req.Header.Get("X-Claude-Code-Session-Id")
	if sess == "" || sess == "client-session-xyz" {
		t.Fatalf("session not normalized: %q", sess)
	}
	// metadata.user_id overwritten: device=SHA256(account), account=ExternalID, session=header.
	m := readBodyJSON(t, req)
	md, _ := m["metadata"].(map[string]any)
	uid, _ := md["user_id"].(string)
	wantUID := "user_" + wantDeviceID("acct_pool_1") + "_account_ext-uuid-1_session_" + sess
	if uid != wantUID {
		t.Fatalf("metadata.user_id=%q want %q (device=SHA256(acct), session=header)", uid, wantUID)
	}
	if strings.Contains(uid, "CLIENTDEVICE") || strings.Contains(uid, "CLIENTSESS") {
		t.Fatalf("client identity leaked through pool normalization: %q", uid)
	}
}

func TestPoolPersona_CollapsesAndDiffersByAccount(t *testing.T) {
	// Same account, repeated → identical (collapse N requests → 1 session/device).
	if poolSessionID("acct_a") != poolSessionID("acct_a") {
		t.Fatal("same account must yield a stable session (collapse)")
	}
	if wantDeviceID("acct_a") != wantDeviceID("acct_a") {
		t.Fatal("same account must yield a stable device")
	}
	// Different accounts → different identity (anti cross-account collision; each
	// account looks like its own device, not one mega-device).
	if poolSessionID("acct_a") == poolSessionID("acct_b") {
		t.Fatal("different accounts must yield different sessions")
	}

	// Persona is stable per account and spreads across the table (anti-千人一面):
	// a batch of accounts must NOT all collapse to one identical persona.
	if personaForAccount("acct_a") != personaForAccount("acct_a") {
		t.Fatal("persona must be stable per account")
	}
	seen := map[poolPersona]bool{}
	for i := 0; i < 40; i++ {
		seen[personaForAccount("acct_spread_"+string(rune('A'+i)))] = true
	}
	if len(seen) < 2 {
		t.Fatalf("personas must vary across accounts (anti-千人一面), got %d distinct", len(seen))
	}
}

// Pooled=true overrides a REAL Claude Code client's identity; Pooled=false leaves
// it untouched (the byte-identical fence for direct-bind / personal OAuth).
func TestInjectClaudeOAuth_PooledGate(t *testing.T) {
	build := func(pooled bool) *http.Request {
		body := `{"model":"claude-3","metadata":{"user_id":"user_REALDEV_account_x_session_REALSESS"},"messages":[]}`
		req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "claude-cli/2.0.0 (external, cli)") // a real CLI
		req.Header.Set("X-Claude-Code-Session-Id", "REALSESS")
		req.Header.Set("X-Stainless-OS", "Windows")
		injectClaudeOAuth(req, &OAuthCredential{
			Provider: "anthropic", AccountID: "acct_z", ExternalID: "ext-z", Pooled: pooled,
		})
		return req
	}

	// Pooled → normalized to acct_z's pinned persona (overriding client Windows;
	// the equality vs the deterministic pick proves the override regardless of
	// whatever OS the persona happens to be).
	p := build(true)
	if got, want := p.Header.Get("X-Stainless-OS"), personaForAccount("acct_z").os; got != want {
		t.Fatalf("pooled: X-Stainless-OS=%q must be overridden to per-account %q", got, want)
	}
	if s := p.Header.Get("X-Claude-Code-Session-Id"); s == "" || s == "REALSESS" {
		t.Fatalf("pooled: session must be normalized (not client REALSESS), got %q", s)
	}
	if uid, _ := readBodyJSON(t, p)["metadata"].(map[string]any)["user_id"].(string); strings.Contains(uid, "REAL") {
		t.Fatalf("pooled: real client identity must be overridden, got %q", uid)
	}

	// Non-pool → client identity preserved (fence: behavior unchanged from before).
	n := build(false)
	if n.Header.Get("X-Claude-Code-Session-Id") != "REALSESS" {
		t.Fatalf("non-pool must preserve client session, got %q", n.Header.Get("X-Claude-Code-Session-Id"))
	}
	if n.Header.Get("X-Stainless-OS") != "Windows" {
		t.Fatalf("non-pool must preserve client OS, got %q", n.Header.Get("X-Stainless-OS"))
	}
	if uid, _ := readBodyJSON(t, n)["metadata"].(map[string]any)["user_id"].(string); uid != "user_REALDEV_account_x_session_REALSESS" {
		t.Fatalf("non-pool must preserve client metadata.user_id, got %q", uid)
	}
}
