package proxy

// B2 VERIFICATION (2026-07-17 review, verify-before-fix): a group OAuth account
// whose material has an EMPTY ExternalID (RW7 admin-enrolled, first-member-login
// backfill not yet propagated to the proxy's ≤60s material rail) must not have a
// broken metadata.user_id injected upstream. The Anthropic OAuth WAF requires
//   user_<64hex>_account_<account_uuid>_session_<uuid>
// and an empty account_uuid draws a 429 business rejection (no rate-limit
// headers → never cooled → sticky re-pick → permanent 429 dead loop).
// Ref: §2.2 audit line 164 + workflow/CI/research/oauth-token-exchange-test.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// bodyCapture records the OUTBOUND request body (post-Director clone).
type bodyCapture struct {
	body string
	auth string
}

func (c *bodyCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		c.body = string(b)
	}
	c.auth = req.Header.Get("Authorization")
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(
			`{"id":"msg","type":"message","content":[{"type":"text","text":"ok"}],"model":"c","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)),
		Request: req,
	}, nil
}

func TestGroupServe_EmptyExternalIDMustNotInjectBrokenUserID(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		// Token PRESENT (member logged in / admin password login) but ExternalID
		// EMPTY — the RW7 backfill-lag window.
		"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "",
		}, "tok-live"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_grouptest": route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	tr := &bodyCapture{}
	p.SetTransport(tr)

	// Non-claude-cli client (no session header) → proxy injects the full persona
	// incl. metadata.user_id.
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(groupBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_grouptest")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	// The guaranteed-WAF-reject shape is "_account__session_" (empty uuid between
	// the two underscores). If this reaches the wire, the account 429s forever
	// with no recovery path (WAF 429 carries no rate-limit signal → not cooled →
	// sticky re-pick of the same account).
	if strings.Contains(tr.body, "_account__session_") {
		t.Fatalf("BUG (B2): empty ExternalID injected a broken metadata.user_id upstream:\nbody=%s", tr.body)
	}
	// Fixed behavior: the picker treats the incomplete material as needs_login →
	// 401 login prompt for THAT account (member sign-in backfills external_id;
	// already-backfilled → self-heals on the next ≤60s material pull). Nothing
	// reaches the upstream.
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("empty-ExternalID account must prompt login (401), got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "acc-1") {
		t.Fatalf("login prompt must name the routed account: %s", w.Body.String())
	}
	if tr.body != "" || tr.auth != "" {
		t.Fatalf("nothing may reach upstream on the login-required path (body=%q auth=%q)", tr.body, tr.auth)
	}
}
