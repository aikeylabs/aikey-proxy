package mcp

// P4 fences 4.F1 / 4.F5, proxy half.
//
// The claim under test is the product's whole reason for existing: a tool
// credential is plaintext ONLY in this process's memory. On disk it is sealed
// with the machine's vault key; in a log it does not appear at all.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sprintf keeps the format verbs in one place.
func sprintf(verb string, v any) string { return fmt.Sprintf(verb, v) }

// theToken is the value that must never be found anywhere but memory.
const theToken = "ghp_PROXYSIDE_PLAINTEXT_MUST_NOT_LAND_7c1d"

// vaultKey is a 32-byte AES key, the shape vault.Encrypt requires.
func vaultKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func newStore(t *testing.T, key []byte) (*CredentialStore, string, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return NewCredentialStore(dir, func() []byte { return key }, logger), dir, logs
}

// ---------------------------------------------------------------------------
// what lands on disk
// ---------------------------------------------------------------------------

// TestCredentialStore_DiskCopyIsSealedAndCarriesNoPlaintext is the fence for
// the sentence the product is sold on.
func TestCredentialStore_DiskCopyIsSealedAndCarriesNoPlaintext(t *testing.T) {
	s, dir, logs := newStore(t, vaultKey())
	s.Replace(context.Background(), []Material{
		{ID: "c1", Kind: "bearer", Secret: theToken},
	})

	path := filepath.Join(dir, credentialCacheFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the sealed cache was not written: %v", err)
	}
	// 🔴 Not a substring, anywhere in the file.
	if bytes.Contains(raw, []byte(theToken)) {
		t.Fatalf("🔴 the credential is on disk in the CLEAR:\n%s", raw)
	}
	if bytes.Contains(raw, []byte("PROXYSIDE_PLAINTEXT")) {
		t.Fatalf("🔴 part of the credential is on disk in the clear:\n%s", raw)
	}
	// ...and the file really does contain the sealed form, so this is not
	// passing because nothing was written.
	var file sealedCache
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("cache is not the documented shape: %v", err)
	}
	if file.Ciphertext == "" || file.Nonce == "" {
		t.Fatal("the cache file has no sealed body — nothing was actually stored")
	}

	// Permissions: another local user must not be able to read it.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the sealed cache is mode %o; it must be 0600 — the seal is not the only "+
			"thing standing between another local account and the customer's tool credentials", perm)
	}
	if strings.Contains(logs.String(), theToken) {
		t.Fatalf("the credential reached the logs:\n%s", logs)
	}
}

// TestCredentialStore_WithoutAVaultKeyNothingIsWrittenAtAll — the fail-safe
// direction.
//
// 🔴 The tempting alternative is "write it unsealed, it's only a cache". That
// would move the secret out of ~/.claude.json and into ~/.aikey/run/ and call
// it a security feature.
func TestCredentialStore_WithoutAVaultKeyNothingIsWrittenAtAll(t *testing.T) {
	s, dir, logs := newStore(t, nil)
	s.Replace(context.Background(), []Material{{ID: "c1", Kind: "bearer", Secret: theToken}})

	if _, err := os.Stat(filepath.Join(dir, credentialCacheFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a proxy with no vault key must write NOTHING; the file exists (%v)", err)
	}
	// It still works in memory — the degradation is a lost restart shortcut,
	// not a lost capability.
	got, err := s.Resolve(context.Background(), "org", "c1")
	if err != nil || got.Secret != theToken {
		t.Fatalf("memory-only resolution must still work: %v / %q", err, got.Secret)
	}
	// And it says so, once, in terms an operator can act on.
	if !strings.Contains(logs.String(), "memory only") {
		t.Fatalf("the operator is never told the cache was skipped:\n%s", logs)
	}
	if strings.Contains(logs.String(), theToken) {
		t.Fatalf("the credential reached the logs:\n%s", logs)
	}
}

// ---------------------------------------------------------------------------
// restore
// ---------------------------------------------------------------------------

func TestCredentialStore_RestoresWhatItSealed(t *testing.T) {
	key := vaultKey()
	s, dir, _ := newStore(t, key)
	s.Replace(context.Background(), []Material{
		{ID: "c1", Kind: "header", HeaderName: "X-Api-Key", Secret: theToken},
	})

	// A fresh process, same machine, same vault.
	next := NewCredentialStore(dir, func() []byte { return key }, slog.Default())
	if n := next.RestoreFromCache(context.Background()); n != 1 {
		t.Fatalf("restored %d credentials, want 1", n)
	}
	got, err := next.Resolve(context.Background(), "org", "c1")
	if err != nil {
		t.Fatalf("resolve after restore: %v", err)
	}
	if got.Secret != theToken || got.Kind != "header" || got.HeaderName != "X-Api-Key" {
		t.Fatalf("restored material is not what was sealed: %+v", got)
	}
}

// TestCredentialStore_ARekeyedVaultDiscardsTheCacheRatherThanFailing — the
// vault was re-keyed, so the cache cannot be opened.
func TestCredentialStore_ARekeyedVaultDiscardsTheCacheRatherThanFailing(t *testing.T) {
	s, dir, _ := newStore(t, vaultKey())
	s.Replace(context.Background(), []Material{{ID: "c1", Kind: "bearer", Secret: theToken}})

	other := make([]byte, 32)
	for i := range other {
		other[i] = 0xAB
	}
	logs := &bytes.Buffer{}
	next := NewCredentialStore(dir, func() []byte { return other },
		slog.New(slog.NewTextHandler(logs, nil)))

	if n := next.RestoreFromCache(context.Background()); n != 0 {
		t.Fatalf("a cache sealed under another key must not restore; got %d", n)
	}
	if next.Count() != 0 {
		t.Fatal("the store must be EMPTY, not partially filled")
	}
	if !strings.Contains(logs.String(), "re-keyed") {
		t.Fatalf("the operator is not told why the credentials vanished:\n%s", logs)
	}
}

// TestCredentialStore_AnExpiredCacheIsRefusedNotUsed.
//
// 🔴 A stale grant is a stale opinion; a stale SECRET is material that may have
// been revoked while the laptop was shut. The bound is the difference.
func TestCredentialStore_AnExpiredCacheIsRefusedNotUsed(t *testing.T) {
	key := vaultKey()
	s, dir, _ := newStore(t, key)
	s.Replace(context.Background(), []Material{{ID: "c1", Kind: "bearer", Secret: theToken}})

	// Rewrite the file's timestamp to well past the bound.
	path := filepath.Join(dir, credentialCacheFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var file sealedCache
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode: %v", err)
	}
	file.WrittenAtMs = time.Now().Add(-30 * 24 * time.Hour).UnixMilli()
	body, _ := json.Marshal(file)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	logs := &bytes.Buffer{}
	next := NewCredentialStore(dir, func() []byte { return key },
		slog.New(slog.NewTextHandler(logs, nil)))
	if n := next.RestoreFromCache(context.Background()); n != 0 {
		t.Fatalf("a month-old credential cache must be refused; restored %d", n)
	}
	if !strings.Contains(logs.String(), "too old") {
		t.Fatalf("the refusal must say WHY:\n%s", logs)
	}
}

// ---------------------------------------------------------------------------
// resolve
// ---------------------------------------------------------------------------

// TestCredentialStore_AMissIsAnErrorNotAnEmptyCredential is the fence that
// keeps an unauthenticated upstream request from ever being attempted.
//
// 🔴 Returning a zero UpstreamCredential would let the caller send a bare
// request; the upstream answers 401; the customer is told their token is wrong
// and rotates a credential that was never the problem.
func TestCredentialStore_AMissIsAnErrorNotAnEmptyCredential(t *testing.T) {
	s, _, logs := newStore(t, vaultKey())
	s.Replace(context.Background(), []Material{{ID: "c1", Kind: "bearer", Secret: theToken}})

	got, err := s.Resolve(context.Background(), "org-1", "c-missing")
	if err == nil {
		t.Fatal("an unresolvable credential must be an ERROR, not an empty credential")
	}
	if !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("the error must be classifiable as ErrCredentialMissing, got %v", err)
	}
	if got.Secret != "" {
		t.Fatal("a failed resolve must return no material")
	}
	// 🔴 The diagnostic must distinguish "the rail never ran" from "this one
	// credential is gone" — the two have completely different fixes.
	if !strings.Contains(err.Error(), "holding 1") {
		t.Fatalf("the error must report how many credentials this proxy holds: %v", err)
	}
	// The WARN carries the event name an operator alerts on...
	if !strings.Contains(logs.String(), "proxy.mcp.credential_resolve_failed") {
		t.Fatalf("the resolve failure must carry its event name:\n%s", logs)
	}
	// ...and never the secret it failed to find, nor the ones it holds.
	if strings.Contains(logs.String(), theToken) {
		t.Fatalf("🔴 the resolve-failure log leaked a credential it DOES hold:\n%s", logs)
	}
}

// TestCredentialStore_ReplaceDropsRevokedMaterial.
//
// 🔴 Replace, not merge. A credential the control plane stopped sending was
// revoked; merging would keep it usable for as long as the process ran, which
// is the exact opposite of what revocation means.
func TestCredentialStore_ReplaceDropsRevokedMaterial(t *testing.T) {
	s, _, _ := newStore(t, vaultKey())
	ctx := context.Background()
	s.Replace(ctx, []Material{
		{ID: "keep", Kind: "bearer", Secret: "keep-me"},
		{ID: "revoked", Kind: "bearer", Secret: theToken},
	})
	if s.Count() != 2 {
		t.Fatalf("precondition: want 2 got %d", s.Count())
	}

	// The next delivery no longer carries the revoked one.
	s.Replace(ctx, []Material{{ID: "keep", Kind: "bearer", Secret: "keep-me"}})

	if _, err := s.Resolve(ctx, "org", "revoked"); err == nil {
		t.Fatal("a credential the control plane stopped delivering must become unresolvable")
	}
	if got, err := s.Resolve(ctx, "org", "keep"); err != nil || got.Secret != "keep-me" {
		t.Fatalf("the surviving credential must still resolve: %v / %q", err, got.Secret)
	}
	if s.Count() != 1 {
		t.Fatalf("Replace must REPLACE, not merge: holding %d", s.Count())
	}
}

// TestUpstreamCredential_CannotBeMarshalledOrPrinted re-asserts, from the
// store's side, the property P3 established on the type: a credential that
// reaches a log or a response by accident is redacted BY CONSTRUCTION.
func TestUpstreamCredential_CannotBeMarshalledOrPrinted(t *testing.T) {
	s, _, _ := newStore(t, vaultKey())
	s.Replace(context.Background(), []Material{{ID: "c1", Kind: "bearer", Secret: theToken}})
	got, err := s.Resolve(context.Background(), "org", "c1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), theToken) {
		t.Fatalf("🔴 the credential serialised: %s", blob)
	}
	for _, verb := range []string{"%v", "%s", "%+v", "%#v"} {
		if printed := sprintf(verb, got); strings.Contains(printed, theToken) {
			t.Fatalf("🔴 %s printed the credential: %s", verb, printed)
		}
	}
}
