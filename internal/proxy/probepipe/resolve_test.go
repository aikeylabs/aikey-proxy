package probepipe

import (
	"errors"
	"net/http"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// stubVaultReader is a focused implementation of VaultReader for tests:
// returns whatever the test set up, no SQLite.
type stubVaultReader struct {
	cred *vault.AliasCredential
	err  error
}

func (s *stubVaultReader) GetAliasCredential(name string) (*vault.AliasCredential, error) {
	return s.cred, s.err
}

func newCtx(alias string) *ProbeContext {
	return &ProbeContext{AliasName: alias, StrippedPath: "/messages"}
}

// TestResolve_ActiveAlias is the happy path: vault returns an active
// credential → Resolve returns the same credential, no error.
func TestResolve_ActiveAlias(t *testing.T) {
	want := &vault.AliasCredential{
		Binding: &vault.ProviderBinding{
			ProviderCode:  "anthropic",
			KeySourceType: "personal_oauth_account",
			KeySourceRef:  "acct-123",
		},
		Status:    "active",
		AliasKind: "oauth",
	}
	got, rerr := Resolve(&stubVaultReader{cred: want}, newCtx("user@host.com"))
	if rerr != nil {
		t.Fatalf("expected no error, got %v", rerr)
	}
	if got != want {
		t.Errorf("expected same credential pointer back, got different")
	}
}

// TestResolve_AliasNotFound maps a nil-credential vault response to 404.
func TestResolve_AliasNotFound(t *testing.T) {
	got, rerr := Resolve(&stubVaultReader{cred: nil}, newCtx("missing"))
	if got != nil {
		t.Fatalf("expected nil credential, got %+v", got)
	}
	if rerr == nil {
		t.Fatalf("expected ResolveError, got nil")
	}
	if rerr.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", rerr.StatusCode)
	}
	if rerr.ErrorCode != "ALIAS_NOT_FOUND" {
		t.Errorf("error code: got %q, want ALIAS_NOT_FOUND", rerr.ErrorCode)
	}
}

// TestResolve_RevokedAlias enforces the revoked-status mapping.
func TestResolve_RevokedAlias(t *testing.T) {
	cred := &vault.AliasCredential{
		Binding:   &vault.ProviderBinding{ProviderCode: "anthropic", KeySourceType: "personal_oauth_account", KeySourceRef: "acct-123"},
		Status:    "revoked",
		AliasKind: "oauth",
	}
	_, rerr := Resolve(&stubVaultReader{cred: cred}, newCtx("user@host.com"))
	if rerr == nil {
		t.Fatalf("expected ResolveError, got nil")
	}
	if rerr.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", rerr.StatusCode)
	}
	if rerr.ErrorCode != "ALIAS_REVOKED" {
		t.Errorf("error code: got %q, want ALIAS_REVOKED", rerr.ErrorCode)
	}
}

// TestResolve_PausedAlias enforces the paused-status mapping.
func TestResolve_PausedAlias(t *testing.T) {
	cred := &vault.AliasCredential{
		Binding:   &vault.ProviderBinding{ProviderCode: "anthropic", KeySourceType: "personal_oauth_account", KeySourceRef: "acct-123"},
		Status:    "paused",
		AliasKind: "oauth",
	}
	_, rerr := Resolve(&stubVaultReader{cred: cred}, newCtx("user@host.com"))
	if rerr == nil {
		t.Fatalf("expected ResolveError, got nil")
	}
	if rerr.ErrorCode != "ALIAS_PAUSED" {
		t.Errorf("error code: got %q, want ALIAS_PAUSED", rerr.ErrorCode)
	}
}

// TestResolve_OtherStatus catches future statuses (e.g. "reauth_required")
// — they all collapse to 403 ALIAS_INACTIVE so an unknown vault status
// never silently routes traffic.
func TestResolve_OtherStatus(t *testing.T) {
	cred := &vault.AliasCredential{
		Binding:   &vault.ProviderBinding{ProviderCode: "anthropic", KeySourceType: "personal_oauth_account", KeySourceRef: "acct-123"},
		Status:    "reauth_required",
		AliasKind: "oauth",
	}
	_, rerr := Resolve(&stubVaultReader{cred: cred}, newCtx("user@host.com"))
	if rerr == nil {
		t.Fatalf("expected ResolveError, got nil")
	}
	if rerr.ErrorCode != "ALIAS_INACTIVE" {
		t.Errorf("error code: got %q, want ALIAS_INACTIVE", rerr.ErrorCode)
	}
}

// TestResolve_VaultReadError surfaces infrastructure failures as 500
// (NOT 404 — we don't know whether the alias exists).
func TestResolve_VaultReadError(t *testing.T) {
	_, rerr := Resolve(&stubVaultReader{err: errors.New("db unreachable")}, newCtx("anything"))
	if rerr == nil {
		t.Fatalf("expected ResolveError, got nil")
	}
	if rerr.StatusCode != http.StatusInternalServerError {
		t.Errorf("status: got %d, want 500", rerr.StatusCode)
	}
	if rerr.ErrorCode != "VAULT_READ_FAILED" {
		t.Errorf("error code: got %q, want VAULT_READ_FAILED", rerr.ErrorCode)
	}
}

// TestResolve_NilReader is the defensive case where SetProbeVault was never
// called. Surfaces as 503 so an operator alert fires and clients see a
// transient-server signal rather than a misleading 404.
func TestResolve_NilReader(t *testing.T) {
	_, rerr := Resolve(nil, newCtx("anything"))
	if rerr == nil {
		t.Fatalf("expected ResolveError, got nil")
	}
	if rerr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503", rerr.StatusCode)
	}
	if rerr.ErrorCode != "PROBE_VAULT_NOT_AVAILABLE" {
		t.Errorf("error code: got %q, want PROBE_VAULT_NOT_AVAILABLE", rerr.ErrorCode)
	}
}
