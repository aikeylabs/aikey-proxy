package supervisor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
