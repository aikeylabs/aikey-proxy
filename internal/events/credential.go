package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Credential is the bearer-token source for a single collector upload.
//
// 2026-05-11 B-phase introduction (see roadmap update
// 20260511-user-jwt-collector-ingest.md). Previously reporter held a
// single global `collector_token` and used it for every route. The new
// model attaches a per-RouteSource credential so team uploads can use
// a user-scoped JWT while personal / oauth keep using the legacy local
// service_token (or none at all).
//
// Two production implementations:
//
//   - StaticTokenCredential — wraps a fixed string (legacy service_token
//     path; trivial Bearer() that just returns the value).
//   - RefreshableJWT — wraps a user JWT with auto-refresh against a
//     control-service POST /v1/auth/cli/token/refresh endpoint. The contract is "ask me
//     right before you send and I will give you a fresh enough token,
//     blocking only as long as a network round-trip in the window
//     before access expires."
//
// The interface is intentionally tiny — concrete types own their own
// locking, refresh state, persistence callbacks. Callers (reporter
// doUpload) just ask for a bearer and forget.
type Credential interface {
	// Bearer returns the current bearer string to put in Authorization:
	// Bearer <…>. Implementations are responsible for any refresh that
	// must happen before the token is safe to use. ctx scoping is for
	// the refresh HTTP call (not the bearer return itself).
	Bearer(ctx context.Context) (string, error)
}

// StaticTokenCredential is the no-refresh case: a fixed string handed
// in at config-load time, returned verbatim on every Bearer() call.
// Used for the legacy global collector_token (service-to-service auth)
// and as a fallback when a RouteSource has no per-route credential.
type StaticTokenCredential struct {
	Token string
}

// Bearer returns the wrapped token. Never errors.
func (s *StaticTokenCredential) Bearer(_ context.Context) (string, error) {
	return s.Token, nil
}

// refreshSkewBeforeExpiry is how far in advance of access_token expiry
// we trigger a refresh. Default 5min — enough margin for clock drift +
// the refresh HTTP round-trip, small enough that we don't over-refresh
// (every Bearer() call hitting the refresh path would defeat the
// purpose of having an access_token at all).
const refreshSkewBeforeExpiry = 5 * time.Minute

// RefreshableJWT is a user-scoped JWT with automatic refresh against a
// control-service POST /v1/auth/cli/token/refresh endpoint. The lifecycle:
//
//  1. proxy startup: loaded from aikey-user.yaml + vault (refresh_token
//     is encrypted in vault; access_token + expires_at are plaintext
//     in user.yaml so proxy doesn't need to decrypt anything on every
//     Bearer() call).
//
//  2. each Bearer() call: if access_token still has more than
//     refreshSkewBeforeExpiry left, return it. Otherwise refresh under
//     lock, persist new access via PersistFn (best-effort), and return
//     the fresh token.
//
//  3. refresh failure: returned to caller. Caller (reporter doUpload)
//     surfaces it as a 401-class upload error so the event lands in
//     dead-letter rather than going out with a stale token that the
//     collector would refuse anyway.
//
// Concurrency: a sync.Mutex guards Token/ExpiresAt mutation. Concurrent
// Bearer() calls serialise but the post-refresh hot path is O(1)
// (single time comparison) and the refresh path runs at most once per
// access lifetime in practice (7 days × Bearer() call rate).
type RefreshableJWT struct {
	mu sync.Mutex

	// AccessToken is the current short-lived bearer. Read on every
	// Bearer() call; rewritten in-place after a successful refresh.
	AccessToken string

	// RefreshToken is the long-lived token used to mint new access
	// tokens. proxy reads this once at startup (from vault) and keeps
	// it in-memory for the lifetime of the process. We deliberately
	// do NOT persist refresh_token rotations back to user.yaml —
	// rotation lands in vault via the CLI on next login.
	RefreshToken string

	// ExpiresAt is the unix time at which AccessToken stops being
	// valid. We refresh when (ExpiresAt - now) < refreshSkewBeforeExpiry.
	ExpiresAt time.Time

	// RefreshURL is the absolute URL the refresh POST hits. Resolved at
	// config-load time from the collector_routes.team URL (e.g.
	// https://control.example.com/v1/auth/cli/token/refresh).
	RefreshURL string

	// HTTPClient lets tests inject a stubbed client. Nil means use the
	// package default (10-second-timeout http.Client).
	HTTPClient *http.Client

	// PersistFn is called after each successful refresh with the new
	// access_token and expires_at. Best-effort — failures are logged
	// but don't fail the Bearer() call. Used to write the new
	// access_token back to aikey-user.yaml so a proxy restart picks up
	// the post-refresh state instead of re-running refresh immediately.
	PersistFn func(accessToken string, expiresAt time.Time) error
}

// Bearer returns a token guaranteed to have at least refreshSkewBeforeExpiry
// validity remaining. Refreshes (under lock, network blocking) when current
// AccessToken is within that window.
func (j *RefreshableJWT) Bearer(ctx context.Context) (string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if time.Until(j.ExpiresAt) > refreshSkewBeforeExpiry {
		return j.AccessToken, nil
	}

	if j.RefreshToken == "" {
		return "", fmt.Errorf("credential: access token within refresh window but no refresh_token available")
	}
	if j.RefreshURL == "" {
		return "", fmt.Errorf("credential: access token within refresh window but no refresh_url configured")
	}

	newAccess, newExpiresAt, err := j.refresh(ctx)
	if err != nil {
		return "", fmt.Errorf("credential: refresh failed: %w", err)
	}
	j.AccessToken = newAccess
	j.ExpiresAt = newExpiresAt

	if j.PersistFn != nil {
		if perr := j.PersistFn(newAccess, newExpiresAt); perr != nil {
			// Persistence failure is non-fatal — the next proxy
			// startup will refresh again at most. Log + continue.
			slog.Warn("credential: post-refresh persist failed",
				"event.name", "credential.persist_failed",
				"error.message", perr.Error(),
			)
		}
	}
	slog.Info("credential: refresh succeeded",
		"event.name", "credential.refresh_succeeded",
		"new_expires_at", newExpiresAt.UTC().Format(time.RFC3339),
	)
	return newAccess, nil
}

// refreshResponse is the wire shape returned by control-service's
// POST /v1/auth/cli/token/refresh endpoint. expires_in is the new access
// token's remaining lifetime in *relative seconds* (OAuth convention),
// identical to the contract the CLI session-refresh already consumes
// (aikey-cli platform_client.rs `RefreshResponse`).
//
// Why relative, not an absolute expires_at: an earlier draft of this
// struct assumed an absolute `expires_at` against a `/auth/refresh`
// endpoint that was never implemented on the server — once the access
// token expired, every refresh failed with "missing expires_at" and
// team usage events were silently dead-lettered. See
// workflow/CI/bugfix/2026-06-03-team-usage-refresh-contract-mismatch.md.
type refreshResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	// Server MAY rotate the refresh token. When present we accept it
	// in-memory but do NOT persist (see RefreshToken docstring).
	RefreshToken string `json:"refresh_token,omitempty"`
}

// refreshRequest body — keep small and JWT-style so the same endpoint
// can later accept OAuth-style refresh_token grants. Today control-
// service treats this as a bearer-style refresh:
// `POST { "refresh_token": "<long>" }`.
type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// refresh POSTs the refresh_token to RefreshURL and parses the new
// access_token. Caller must hold the lock.
func (j *RefreshableJWT) refresh(ctx context.Context) (string, time.Time, error) {
	body, err := json.Marshal(refreshRequest{RefreshToken: j.RefreshToken})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("marshal refresh body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.RefreshURL, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := j.HTTPClient
	if client == nil {
		client = defaultRefreshClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", time.Time{}, fmt.Errorf("refresh HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out refreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", time.Time{}, fmt.Errorf("decode response: %w", err)
	}
	if out.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("refresh response missing access_token")
	}
	if out.ExpiresIn == 0 {
		return "", time.Time{}, fmt.Errorf("refresh response missing expires_in")
	}
	// Defense-in-depth: in-memory accept refresh_token rotation.
	if out.RefreshToken != "" {
		j.RefreshToken = out.RefreshToken
	}
	// expires_in is relative seconds; convert to an absolute deadline so
	// Bearer()'s `time.Until(ExpiresAt)` window check works.
	return out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn) * time.Second), nil
}

// defaultRefreshClient is the http.Client used when RefreshableJWT
// callers don't inject one. Short timeout because refresh is on the
// hot path of every upload right at the edge of the access token's
// validity window — a stuck refresh would block uploads. 10s is the
// same shape as the reporter's batch-upload client.
var defaultRefreshClient = &http.Client{
	Timeout: 10 * time.Second,
}
