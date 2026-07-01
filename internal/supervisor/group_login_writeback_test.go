package supervisor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fastBackoff shrinks the retry backoff for tests + restores it after.
func fastBackoff(t *testing.T) {
	t.Helper()
	prev := writebackBaseBackoff
	writebackBaseBackoff = time.Millisecond
	t.Cleanup(func() { writebackBaseBackoff = prev })
}

// TestPostMemberToken_PostsToMasterWithBearer: the writeback POSTs the per-member
// token to master's RW10 endpoint with the account-JWT Bearer + JSON body, and the
// token is sent ONLY in the request body (never echoed anywhere). 2xx → nil error.
func TestPostMemberToken_PostsToMasterWithBearer(t *testing.T) {
	var gotAuth, gotPath, gotCT string
	var gotBody memberTokenWriteback
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	wb := memberTokenWriteback{CredentialID: "c1", AccessToken: "tok", RefreshToken: "rt", ExpiresAt: 100, ExternalID: "uuid-1"}
	if err := postMemberToken(context.Background(), srv.Client(), srv.URL, "JWT123", wb); err != nil {
		t.Fatalf("postMemberToken: %v", err)
	}
	if gotPath != "/accounts/me/oauth-member-token" {
		t.Errorf("path = %q, want /accounts/me/oauth-member-token", gotPath)
	}
	if gotAuth != "Bearer JWT123" {
		t.Errorf("auth = %q, want Bearer JWT123", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q", gotCT)
	}
	if gotBody.CredentialID != "c1" || gotBody.AccessToken != "tok" || gotBody.ExternalID != "uuid-1" {
		t.Errorf("body mismatch: %+v", gotBody)
	}
}

// TestPostMemberToken_Non2xxSurfaces: a master error (e.g. 403 forbidden) is
// surfaced, not swallowed (the carry-back is auditable; the member can retry).
func TestPostMemberToken_Non2xxSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"BIZ_OAUTH_MEMBER_TOKEN_FORBIDDEN"}}`))
	}))
	defer srv.Close()

	err := postMemberToken(context.Background(), srv.Client(), srv.URL, "JWT", memberTokenWriteback{CredentialID: "c1", AccessToken: "t"})
	if err == nil {
		t.Fatal("non-2xx master response must surface as an error")
	}
}

// TestPostMemberToken_RetriesTransient5xxThenSucceeds: a TRANSIENT master failure
// (5xx while the VM restarts / nginx backend flaps) is retried; once the master
// recovers the writeback lands. The OAuth code was already consumed, so this is the
// whole point — a blip must not waste it. 防退化 for the 2026-06-30 retry.
func TestPostMemberToken_RetriesTransient5xxThenSucceeds(t *testing.T) {
	fastBackoff(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 → transient → retry
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := postMemberToken(context.Background(), srv.Client(), srv.URL, "JWT", memberTokenWriteback{CredentialID: "c1", AccessToken: "t"}); err != nil {
		t.Fatalf("expected success after transient 5xx, got: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("server hit %d times, want 3 (2 transient + 1 success)", got)
	}
}

// TestPostMemberToken_4xxFailsFastNoRetry: a 4xx is PERMANENT — retrying can't help,
// so we must fail on the FIRST attempt (no wasted retries / latency).
func TestPostMemberToken_4xxFailsFastNoRetry(t *testing.T) {
	fastBackoff(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadRequest) // 400 → permanent
	}))
	defer srv.Close()

	if err := postMemberToken(context.Background(), srv.Client(), srv.URL, "JWT", memberTokenWriteback{CredentialID: "c1", AccessToken: "t"}); err == nil {
		t.Fatal("4xx must surface as an error")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("server hit %d times, want 1 (4xx must NOT retry)", got)
	}
}

// TestPostMemberToken_ExhaustsRetriesOnPersistent5xx: a master that stays down
// exhausts all attempts and returns an error (bounded, doesn't hang forever).
func TestPostMemberToken_ExhaustsRetriesOnPersistent5xx(t *testing.T) {
	fastBackoff(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadGateway) // 502 → transient, but never recovers
	}))
	defer srv.Close()

	if err := postMemberToken(context.Background(), srv.Client(), srv.URL, "JWT", memberTokenWriteback{CredentialID: "c1", AccessToken: "t"}); err == nil {
		t.Fatal("persistent 5xx must surface as an error after exhausting retries")
	}
	if got := atomic.LoadInt32(&hits); got != writebackMaxAttempts {
		t.Errorf("server hit %d times, want %d (all attempts)", got, writebackMaxAttempts)
	}
}
