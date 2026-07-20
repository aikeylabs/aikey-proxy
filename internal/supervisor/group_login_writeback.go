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
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
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
	// ProviderCode and Identity come from the immutable login session context.
	// Master re-validates ProviderCode before persistence; Identity stays advisory
	// under the availability-first mismatch policy but is never inferred later.
	ProviderCode string `json:"provider_code,omitempty"`
	OauthGroupID string `json:"oauth_group_id,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Identity     string `json:"identity,omitempty"`
}

// poolLoginContext is the non-secret master binding fetched before starting an
// OAuth provider flow. It prevents UI display fallbacks from selecting a model.
type poolLoginContext struct {
	CredentialID     string `json:"credential_id"`
	OauthGroupID     string `json:"oauth_group_id"`
	AccountID        string `json:"account_id"`
	ProviderCode     string `json:"provider_code"`
	ExpectedIdentity string `json:"expected_identity"`
	ExternalID       string `json:"external_id"`
}

type poolLoginContextHTTPError struct {
	StatusCode int
	Detail     string
}

func (e *poolLoginContextHTTPError) Error() string {
	return fmt.Sprintf("master OAuth login-context failed: %d: %s", e.StatusCode, e.Detail)
}

func fetchPoolLoginContext(ctx context.Context, client *http.Client, masterURL, bearer, credentialID string) (poolLoginContext, error) {
	u := masterURL + "/accounts/me/oauth-login-context?credential_id=" + url.QueryEscape(credentialID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return poolLoginContext{}, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := client.Do(req)
	if err != nil {
		return poolLoginContext{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return poolLoginContext{}, &poolLoginContextHTTPError{StatusCode: resp.StatusCode, Detail: string(snippet)}
	}
	var out poolLoginContext
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&out); err != nil {
		return poolLoginContext{}, fmt.Errorf("decode master OAuth login-context: %w", err)
	}
	if out.CredentialID != credentialID || out.ProviderCode == "" || out.OauthGroupID == "" || out.AccountID == "" {
		return poolLoginContext{}, fmt.Errorf("master OAuth login-context incomplete for credential %q", credentialID)
	}
	return out, nil
}

// writebackMaxAttempts / writebackBaseBackoff / writebackMaxBackoff bound the retry
// window: 6 attempts with 500ms base doubling capped at 3s wait ~0.5+1+2+3+3 = 9.5s
// of backoff (plus per-try request time). Short enough that the member isn't left
// hanging, long enough to ride out the post-recovery ARP transient + a quick master
// restart.
const (
	writebackMaxAttempts = 6
	// writebackMaxBackoff caps the per-retry wait so the backoff doesn't grow
	// unbounded; over 6 attempts the waits are 0.5,1,2,3,3 ⇒ ~9.5s total. Sized to
	// ride out a master that JUST came back: a route/ARP recovery has a ~1-2s window
	// where a fresh Go dial still gets EHOSTUNREACH (curl retries past it; verified
	// 2026-06-30 reproduction), plus a quick container/service restart. It does NOT
	// cover a multi-minute VM redeploy — that needs the master up before login.
	writebackMaxBackoff = 3 * time.Second
)

// writebackBaseBackoff is a var (not const) only so tests can shrink it; production
// keeps 500ms (×2 each retry, capped at writebackMaxBackoff).
var writebackBaseBackoff = 500 * time.Millisecond

// postMemberToken POSTs the freshly-exchanged per-member token to master's RW10
// endpoint with the team account-JWT Bearer. clientFn is injected for testability
// and is RE-RESOLVED every attempt (production passes groupRuntimeClient, the
// live swappable accessor) so a client rebuilt mid-retry takes effect on the
// next try.
//
// RETRY (2026-06-30): the OAuth exchange already CONSUMED the one-shot auth code,
// so a TRANSIENT master blip (the VM restarting → "no route to host", or a 5xx
// while nginx is up but the backend isn't) must NOT waste it — we retry with
// exponential backoff. A 4xx is PERMANENT (bad request / auth / validation):
// retrying can't help, so we fail fast. The write is idempotent on master via the
// (credential_id, seat) PK, so re-POSTing the same token is safe.
//
// SELF-HEAL (2026-07-01): a routing-layer dial error (no-route/EHOSTUNREACH) can
// mean the long-lived client went stale after a host network change while master
// is actually reachable. We rebuild the shared client mid-retry so subsequent
// attempts (and later polls) dial clean instead of burning all 6 tries on a dead
// transport. The guarded self-restart backstop (selfheal.go) covers the case
// where even a rebuilt in-process client stays stuck.
func postMemberToken(ctx context.Context, clientFn func() *http.Client, masterURL, bearer string, wb memberTokenWriteback) error {
	body, err := json.Marshal(wb)
	if err != nil {
		return err
	}
	backoff := writebackBaseBackoff
	var lastErr error
	for attempt := 1; attempt <= writebackMaxAttempts; attempt++ {
		status, err := writeMemberTokenOnce(ctx, clientFn(), masterURL, bearer, body)
		if err == nil {
			return nil
		}
		lastErr = err
		// Permanent client error (4xx) — retrying won't help; surface immediately.
		if status >= 400 && status < 500 {
			return err
		}
		// Network-change dial error → swap in a fresh control-plane client so the
		// NEXT clientFn() call dials clean (WARN, not silent — logging-conventions).
		if isNetChangeDialErr(err) {
			slog.Warn("control-plane client rebuilt after network-change dial error",
				"event.name", observability.EventProxyControlPlaneClientRebuilt, "caller", "member_token_writeback",
				"credential_id", wb.CredentialID, "error", err.Error())
			httpx.RebuildAllControlPlane()
		}
		if attempt == writebackMaxAttempts {
			break
		}
		slog.Warn("broker.pool.writeback_retry",
			"attempt", attempt, "max", writebackMaxAttempts, "next_backoff", backoff.String(),
			"credential_id", wb.CredentialID, "error", err.Error())
		select {
		case <-ctx.Done():
			return fmt.Errorf("member-token writeback aborted (attempt %d/%d): %w; last error: %v",
				attempt, writebackMaxAttempts, ctx.Err(), lastErr)
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > writebackMaxBackoff {
			backoff = writebackMaxBackoff
		}
	}
	return fmt.Errorf("member-token writeback failed after %d attempts: %w", writebackMaxAttempts, lastErr)
}

// writeMemberTokenOnce performs ONE writeback POST. Returns (statusCode, err):
// statusCode is 0 on a transport/connection error (err set, transient); on a
// non-2xx HTTP response statusCode is the code and err carries the body; on 2xx
// err is nil.
func writeMemberTokenOnce(ctx context.Context, client *http.Client, masterURL, bearer string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, masterURL+"/accounts/me/oauth-member-token", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err // transport / connection error (e.g. "no route to host") → transient
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read a bounded slice of the error body for the log/return (master sends a
		// structured {"error":{code,message}} — surface it, don't swallow).
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return resp.StatusCode, fmt.Errorf("master member-token writeback failed: %d: %s", resp.StatusCode, string(snippet))
	}
	return resp.StatusCode, nil
}
