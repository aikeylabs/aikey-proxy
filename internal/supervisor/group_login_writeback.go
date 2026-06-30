// group_login_writeback.go — RW8 (Path α, proxy-orchestrated): after the proxy's
// broker exchanges a member's per-account OAuth login, the resulting token is
// written BACK to master (RW10 POST /accounts/me/oauth-member-token) so it lands
// in oauth_member_token — NOT in the proxy's personal vault, and NEVER returned to
// any HTTP caller. The proxy is the only local component that holds the team
// account-JWT (RefreshableJWT) + reaches master, so it owns this writeback.
//
// SECURITY: the token travels proxy→master over TLS only. There is deliberately
// no path that hands the plaintext token back to the contribute page / browser
// (that would be the Path β localhost-token-leak we rejected). refresh_token is
// included only because master is its authoritative store — it is never delivered
// back down to any proxy/client (channel ③ omits it).
package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// memberTokenWriteback is the RW10 request body (mirrors api.MemberTokenHandler).
type memberTokenWriteback struct {
	CredentialID string `json:"credential_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	// ExternalID (optional, C5): the provider account UUID from the exchange, so
	// master backfills it on first login (Claude metadata.user_id).
	ExternalID string `json:"external_id,omitempty"`
}

// postMemberToken POSTs the freshly-exchanged per-member token to master's RW10
// endpoint with the team account-JWT Bearer. client is injected for testability
// (production passes groupRuntimeHTTPClient). A non-2xx is an error so the caller
// surfaces the failure (the exchange already happened; the member can retry — the
// write is idempotent on master via the (credential_id, seat) PK).
func postMemberToken(ctx context.Context, client *http.Client, masterURL, bearer string, wb memberTokenWriteback) error {
	body, err := json.Marshal(wb)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, masterURL+"/accounts/me/oauth-member-token", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read a bounded slice of the error body for the log/return (master sends a
		// structured {"error":{code,message}} — surface it, don't swallow).
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return fmt.Errorf("master member-token writeback failed: %d: %s", resp.StatusCode, string(snippet))
	}
	return nil
}
