package events

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── StaticTokenCredential ───────────────────────────────────────────────

func TestStaticTokenCredential_Bearer_ReturnsToken(t *testing.T) {
	c := &StaticTokenCredential{Token: "sk-abc"}
	got, err := c.Bearer(context.Background())
	if err != nil {
		t.Fatalf("Bearer: %v", err)
	}
	if got != "sk-abc" {
		t.Fatalf("got %q, want sk-abc", got)
	}
}

func TestStaticTokenCredential_Bearer_EmptyTokenIsValid(t *testing.T) {
	// Empty token is a legitimate state (no auth header path); Bearer
	// must not error. doUpload handles "" by skipping Authorization.
	c := &StaticTokenCredential{}
	got, err := c.Bearer(context.Background())
	if err != nil {
		t.Fatalf("Bearer: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty bearer, got %q", got)
	}
}

// ── RefreshableJWT: fast-path (no refresh needed) ──────────────────────

func TestRefreshableJWT_Bearer_ReturnsAccessWhenFresh(t *testing.T) {
	j := &RefreshableJWT{
		AccessToken:  "fresh-access",
		RefreshToken: "long-refresh",
		// Far in the future — well beyond refreshSkewBeforeExpiry.
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		RefreshURL: "http://nope.invalid/auth/refresh",
	}
	got, err := j.Bearer(context.Background())
	if err != nil {
		t.Fatalf("Bearer: %v", err)
	}
	if got != "fresh-access" {
		t.Fatalf("got %q, want fresh-access", got)
	}
}

// ── RefreshableJWT: refresh trigger ────────────────────────────────────

// refreshServer returns an httptest server that pretends to be
// control-service's /auth/refresh. callCount lets tests assert
// "refresh was actually hit" / "refresh ran exactly once".
type refreshServerSpy struct {
	calls    atomic.Int32
	respFn   func(req refreshRequest) (refreshResponse, int)
	receivedRefreshTokens []string
	mu       sync.Mutex
}

func newRefreshServer(t *testing.T, respFn func(req refreshRequest) (refreshResponse, int)) (*httptest.Server, *refreshServerSpy) {
	spy := &refreshServerSpy{respFn: respFn}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spy.calls.Add(1)
		var req refreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		spy.mu.Lock()
		spy.receivedRefreshTokens = append(spy.receivedRefreshTokens, req.RefreshToken)
		spy.mu.Unlock()
		resp, status := respFn(req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, spy
}

func TestRefreshableJWT_Bearer_RefreshesWhenWithinSkewWindow(t *testing.T) {
	srv, spy := newRefreshServer(t, func(_ refreshRequest) (refreshResponse, int) {
		return refreshResponse{
			AccessToken: "rotated-access",
			ExpiresAt:   time.Now().Add(7 * 24 * time.Hour).Unix(),
		}, http.StatusOK
	})

	var persisted atomic.Value // stores []any{access, expiresAt}
	j := &RefreshableJWT{
		AccessToken:  "stale-access",
		RefreshToken: "long-refresh",
		// 1 minute remaining — INSIDE the 5min skew window.
		ExpiresAt:  time.Now().Add(1 * time.Minute),
		RefreshURL: srv.URL,
		PersistFn: func(at string, exp time.Time) error {
			persisted.Store([]any{at, exp})
			return nil
		},
	}

	got, err := j.Bearer(context.Background())
	if err != nil {
		t.Fatalf("Bearer: %v", err)
	}
	if got != "rotated-access" {
		t.Fatalf("got %q, want rotated-access", got)
	}
	if c := spy.calls.Load(); c != 1 {
		t.Fatalf("refresh hit %d times, want 1", c)
	}
	if persisted.Load() == nil {
		t.Fatal("PersistFn was not invoked after successful refresh")
	}

	// Second Bearer() call: post-refresh ExpiresAt is far in the future,
	// so we should NOT refresh again.
	got2, err := j.Bearer(context.Background())
	if err != nil {
		t.Fatalf("second Bearer: %v", err)
	}
	if got2 != "rotated-access" {
		t.Fatalf("second call should return cached new access, got %q", got2)
	}
	if c := spy.calls.Load(); c != 1 {
		t.Fatalf("refresh ran %d times across two Bearer() calls, want 1", c)
	}
}

// ── RefreshableJWT: server error propagation ───────────────────────────

func TestRefreshableJWT_Bearer_RefreshHTTPErrorPropagates(t *testing.T) {
	srv, _ := newRefreshServer(t, func(_ refreshRequest) (refreshResponse, int) {
		return refreshResponse{}, http.StatusUnauthorized
	})

	j := &RefreshableJWT{
		AccessToken:  "stale",
		RefreshToken: "expired-refresh-token",
		ExpiresAt:    time.Now().Add(1 * time.Minute),
		RefreshURL:   srv.URL,
	}

	_, err := j.Bearer(context.Background())
	if err == nil {
		t.Fatal("Bearer must surface refresh HTTP errors")
	}
	// Error message should be actionable — bubble up the HTTP status so
	// dead-letter diagnostics can show "401 from control-service" not
	// just "credential refresh failed".
	if !contains(err.Error(), "401") {
		t.Fatalf("error should mention HTTP status, got: %v", err)
	}
}

func TestRefreshableJWT_Bearer_RefreshMissingAccessTokenInResponse(t *testing.T) {
	srv, _ := newRefreshServer(t, func(_ refreshRequest) (refreshResponse, int) {
		// 200 but no access_token — a malformed control-service response.
		return refreshResponse{ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Unix()}, http.StatusOK
	})

	j := &RefreshableJWT{
		AccessToken:  "stale",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(1 * time.Minute),
		RefreshURL:   srv.URL,
	}

	_, err := j.Bearer(context.Background())
	if err == nil {
		t.Fatal("missing access_token in 200 response must error")
	}
	if !contains(err.Error(), "access_token") {
		t.Fatalf("error should name missing field, got: %v", err)
	}
}

// ── RefreshableJWT: refresh_token rotation ────────────────────────────

func TestRefreshableJWT_Bearer_AcceptsRotatedRefreshTokenInMemory(t *testing.T) {
	// Server rotates refresh_token on each call. We expect in-memory
	// update so a subsequent (forced) refresh uses the new value, but
	// we explicitly do NOT call PersistFn for refresh_token (it's
	// in-memory only — vault is the persistent store).
	srv, spy := newRefreshServer(t, func(req refreshRequest) (refreshResponse, int) {
		// Echo the received refresh_token back as the new one — lets us
		// verify the server saw whatever the client most recently held.
		return refreshResponse{
			AccessToken:  "fresh",
			RefreshToken: "rotated-from-" + req.RefreshToken,
			ExpiresAt:    time.Now().Add(7 * 24 * time.Hour).Unix(),
		}, http.StatusOK
	})

	j := &RefreshableJWT{
		AccessToken:  "stale",
		RefreshToken: "rt-v1",
		ExpiresAt:    time.Now().Add(1 * time.Minute),
		RefreshURL:   srv.URL,
	}

	// First refresh
	if _, err := j.Bearer(context.Background()); err != nil {
		t.Fatalf("first Bearer: %v", err)
	}
	if j.RefreshToken != "rotated-from-rt-v1" {
		t.Fatalf("in-memory refresh_token not rotated, still: %q", j.RefreshToken)
	}

	// Force another refresh by rewinding ExpiresAt
	j.mu.Lock()
	j.ExpiresAt = time.Now().Add(1 * time.Minute)
	j.mu.Unlock()
	if _, err := j.Bearer(context.Background()); err != nil {
		t.Fatalf("second Bearer: %v", err)
	}
	if j.RefreshToken != "rotated-from-rotated-from-rt-v1" {
		t.Fatalf("second rotation did not happen, refresh_token: %q", j.RefreshToken)
	}

	// Server must have received the rotated value on the 2nd call.
	spy.mu.Lock()
	defer spy.mu.Unlock()
	if len(spy.receivedRefreshTokens) != 2 {
		t.Fatalf("expected 2 server calls, got %d", len(spy.receivedRefreshTokens))
	}
	if spy.receivedRefreshTokens[1] != "rotated-from-rt-v1" {
		t.Fatalf("second call did not use rotated rt, got: %q", spy.receivedRefreshTokens[1])
	}
}

// ── RefreshableJWT: misconfiguration errors ────────────────────────────

func TestRefreshableJWT_Bearer_NoRefreshTokenErrors(t *testing.T) {
	j := &RefreshableJWT{
		AccessToken: "stale",
		// No RefreshToken field — common state right after a partial
		// CLI write that wrote access but not refresh. Bearer must
		// fail loud rather than send a stale token to the collector.
		ExpiresAt:  time.Now().Add(1 * time.Minute),
		RefreshURL: "http://nope.invalid/auth/refresh",
	}
	_, err := j.Bearer(context.Background())
	if err == nil {
		t.Fatal("missing refresh_token should error")
	}
}

func TestRefreshableJWT_Bearer_NoRefreshURLErrors(t *testing.T) {
	j := &RefreshableJWT{
		AccessToken:  "stale",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(1 * time.Minute),
		// No RefreshURL — bug in config loader; we'd rather error than
		// blow up with an opaque http error message.
	}
	_, err := j.Bearer(context.Background())
	if err == nil {
		t.Fatal("missing refresh_url should error")
	}
}

// ── RefreshableJWT: concurrency ────────────────────────────────────────

func TestRefreshableJWT_Bearer_ConcurrentCallsRefreshOnce(t *testing.T) {
	// Stale refresh window + N concurrent Bearer() calls = exactly 1
	// refresh hit. Property of the in-struct mutex; this test catches
	// any future "lock release before HTTP call returns" regression.
	srv, spy := newRefreshServer(t, func(_ refreshRequest) (refreshResponse, int) {
		// Slow the response so all goroutines have a chance to queue up
		// behind the mutex (a fast response could let goroutine #2 see
		// the post-refresh ExpiresAt before its own lock acquire).
		time.Sleep(100 * time.Millisecond)
		return refreshResponse{
			AccessToken: "fresh",
			ExpiresAt:   time.Now().Add(7 * 24 * time.Hour).Unix(),
		}, http.StatusOK
	})

	j := &RefreshableJWT{
		AccessToken:  "stale",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(1 * time.Minute),
		RefreshURL:   srv.URL,
	}

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = j.Bearer(context.Background())
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
	if c := spy.calls.Load(); c != 1 {
		t.Fatalf("expected exactly 1 refresh across %d concurrent callers, got %d", n, c)
	}
}

// ── RefreshableJWT: persist failure non-fatal ─────────────────────────

func TestRefreshableJWT_Bearer_PersistFailureDoesNotBlock(t *testing.T) {
	srv, _ := newRefreshServer(t, func(_ refreshRequest) (refreshResponse, int) {
		return refreshResponse{
			AccessToken: "fresh",
			ExpiresAt:   time.Now().Add(7 * 24 * time.Hour).Unix(),
		}, http.StatusOK
	})

	j := &RefreshableJWT{
		AccessToken:  "stale",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(1 * time.Minute),
		RefreshURL:   srv.URL,
		PersistFn: func(_ string, _ time.Time) error {
			return fmt.Errorf("disk full or whatever")
		},
	}

	got, err := j.Bearer(context.Background())
	if err != nil {
		t.Fatalf("persist failure should not propagate as Bearer error: %v", err)
	}
	if got != "fresh" {
		t.Fatalf("got %q, want fresh", got)
	}
	// In-memory state is correct even if persist failed — next Bearer()
	// from this same proxy instance will hit the cache, not re-refresh.
	if j.AccessToken != "fresh" {
		t.Fatalf("in-memory AccessToken not updated: %q", j.AccessToken)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) &&
		(haystack == needle ||
			indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
