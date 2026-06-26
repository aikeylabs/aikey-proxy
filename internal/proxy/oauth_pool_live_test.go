package proxy

// Live disguise validation (opt-in): does the per-account AccountPersona disguise
// the proxy applies to a POOLED Claude account actually pass real Anthropic?
//
// This is the 防封-critical question the full E2E proxy leg exists to answer. It
// uses the REAL injection path (oauthInject → injectClaudeOAuth + applyPoolPersona)
// on a real /v1/messages request with a real pooled account's Setup Token, sends
// it to api.anthropic.com, and asserts a 200 — i.e. the disguised request is
// indistinguishable-enough from a real Claude Code client that the OAuth WAF
// accepts it.
//
// Gated by env so it never runs in normal `go test` (it makes a real, billed
// upstream call with a real credential):
//
//	AIKEY_LIVE_ANTHROPIC=1
//	AIKEY_LIVE_TOKEN=<access_token>
//	AIKEY_LIVE_ACCOUNT_ID=<provider_account_id>   (device_id seed)
//	AIKEY_LIVE_EXTERNAL_ID=<claude account uuid>  (metadata.user_id)
//
// A 200 confirms the pool disguise works end-to-end against production Anthropic.
// A 429 with no anthropic-ratelimit-* headers = business rejection (persona not
// accepted). A 401/403 = token/permission issue (not a disguise failure).

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLive_PoolDisguisePassesAnthropic(t *testing.T) {
	if os.Getenv("AIKEY_LIVE_ANTHROPIC") != "1" {
		t.Skip("set AIKEY_LIVE_ANTHROPIC=1 (+ AIKEY_LIVE_TOKEN/ACCOUNT_ID/EXTERNAL_ID) to run the live disguise test")
	}
	token := os.Getenv("AIKEY_LIVE_TOKEN")
	accountID := os.Getenv("AIKEY_LIVE_ACCOUNT_ID")
	externalID := os.Getenv("AIKEY_LIVE_EXTERNAL_ID")
	if token == "" || accountID == "" || externalID == "" {
		t.Fatal("AIKEY_LIVE_TOKEN, AIKEY_LIVE_ACCOUNT_ID, AIKEY_LIVE_EXTERNAL_ID are required")
	}

	// Minimal haiku request (haiku is exempt from the WAF body-fingerprint gate,
	// so this isolates the device/session/OS disguise — exactly what we're testing).
	body := `{"model":"claude-haiku-4-5-20251001","messages":[{"role":"user","content":"hi"}],"max_tokens":1}`
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Inbound is a non-claude-cli client (a pooled employee on a third-party tool)
	// so the full persona is injected, then the pool disguise overrides identity —
	// the realistic worst case.
	req.Header.Set("User-Agent", "some-third-party-tool/1.0")

	cred := &OAuthCredential{AccessToken: token, Provider: "anthropic", AccountID: accountID, ExternalID: externalID}

	// EXACT proxy outbound: oauthInject (Claude persona) then the pool disguise
	// (per-account device/session/OS + metadata.user_id), mirroring N8b + NP-4.
	oauthInject(req, cred, "anthropic")
	applyPoolPersona(req, accountID, externalID)

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("upstream call failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	// Report the persona we sent (no token) + the upstream verdict.
	t.Logf("disguise sent: UA=%q X-Stainless-OS=%q session=%q",
		req.Header.Get("User-Agent"), req.Header.Get("X-Stainless-OS"), req.Header.Get("X-Claude-Code-Session-Id"))
	t.Logf("anthropic status=%d ratelimit-reset=%q body=%.300s",
		resp.StatusCode, resp.Header.Get("anthropic-ratelimit-requests-reset"), string(respBody))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pool disguise REJECTED by Anthropic: status=%d (200 expected). body=%.400s", resp.StatusCode, string(respBody))
	}
	t.Log("✅ pool disguise ACCEPTED by real Anthropic (200)")
}
