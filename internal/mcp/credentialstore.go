package mcp

// credentialstore.go — P4 tasks 4.5 / 4.10. The proxy's half of credential
// custody.
//
// # The one property this file exists to hold
//
// 🔴 A backend credential's PLAINTEXT lives only in this process's memory, only
// between the moment the control plane delivers it and the moment the process
// exits. On disk it is sealed with the machine's vault key — a key the control
// plane does not have — and it is never written to a log, an error string, or
// any response.
//
// That is the whole product claim. Today a GitHub PAT with write scope sits in
// cleartext in every developer's ~/.claude.json; the gateway is only worth
// deploying if the thing that replaces it does not do the same.
//
// # Why a sealed FILE and not a vault table
//
// Same reasoning P2 recorded for the policy cache (policycache.go), plus one
// more that matters here: the vault schema is owned by aikey-cli's Rust
// migrations — a released, one-way-door schema in another repository and
// another language. This data is a CACHE. It is reconstructible from the
// control plane in one poll, deleting it is supported, and it must never be
// authoritative. Committing a permanent migrated schema to hold something
// disposable is exactly the trade 慎重建表 exists to prevent.
//
// 🔴 The difference from the policy cache — and it is not a small one — is that
// this file holds SECRETS, so unlike the policy cache it is ENCRYPTED at rest,
// with the same AES-256-GCM vault key the group-runtime material already uses.
// A plaintext cache here would move the secret from ~/.claude.json to
// ~/.aikey/run/ and call it a feature.
//
// # Failure posture
//
//	read fails   → empty store, WARN. Backends needing credentials answer
//	               MCP_CREDENTIAL_MISSING with an actionable message until the
//	               next poll. 🚫 Never a silent empty success.
//	write fails  → WARN, carry on. Memory is already correct; only the restart
//	               shortcut is lost.
//	main path    → the LLM forwarding path never touches this file.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// credentialCacheFilename is the sealed cache under the run directory.
//
// The `.enc` suffix is load-bearing documentation: anyone who finds this file
// while poking around should be able to tell at a glance that its contents are
// not meant to be readable, and a support engineer asking a customer to send
// their run directory should see immediately that they are asking for
// ciphertext.
const credentialCacheFilename = "mcp-credentials.enc"

// Material is one credential as the control plane delivers it.
//
// 🔴 Field-for-field identical to mcpgateway.Material on the control-plane
// side. Deliberately re-declared rather than imported: the proxy does not
// import the control plane, and a shared wire struct across that boundary would
// couple a customer-installed binary to a server package's release cadence.
// The wire contract is the JSON, and the fence over it is
// TestCredentialRail_WireShapeMatchesTheControlPlane.
type Material struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	HeaderName string `json:"header_name,omitempty"`
	Secret     string `json:"secret"`
}

// CredentialStore holds resolved backend credentials in memory and keeps a
// sealed copy on disk for restarts.
//
// It implements CredentialResolver.
type CredentialStore struct {
	logger *slog.Logger
	runDir string
	// sealKey RESOLVES the vault-derived AES key at each use, rather than
	// holding a copy.
	//
	// 🔴 A provider, not a value. The vault is unlocked and re-keyed
	// independently of this store's lifetime, and a key captured at boot would
	// keep sealing with a key the vault no longer uses — producing a cache that
	// writes successfully forever and can never be read back. The symptom would
	// be "credentials are always empty after a restart", with nothing failing.
	//
	// Returning nil is legitimate (no unlocked vault) and means memory-only.
	// 🔴 nil must NOT mean "write it in the clear": a proxy that cannot seal
	// keeps its credentials in memory, which costs a re-poll after a restart
	// and leaks nothing.
	sealKey func() []byte
	maxAge  time.Duration

	mu    sync.RWMutex
	creds map[string]UpstreamCredential
	// loadedAt is when the current set arrived, for /health/mcp.
	loadedAt time.Time
	// warnedNoSealKey keeps the "cannot persist" message to once per process.
	warnedNoSealKey bool
}

// NewCredentialStore builds an empty store.
//
// sealKey may be nil (a proxy with no unlocked vault); runDir may be empty (no
// persistence at all). Neither is an error: the store degrades to
// memory-only, which is the safe direction.
func NewCredentialStore(runDir string, sealKey func() []byte, logger *slog.Logger) *CredentialStore {
	if logger == nil {
		logger = slog.Default()
	}
	if sealKey == nil {
		sealKey = func() []byte { return nil }
	}
	return &CredentialStore{
		logger:  logger,
		runDir:  runDir,
		sealKey: sealKey,
		// 🔴 Bounded for the same reason the policy cache is: a laptop that was
		// shut for three weeks must not come back injecting three-week-old
		// secrets into a customer's systems. Beyond the bound the store starts
		// empty and waits for a real poll — tools fail loudly rather than
		// working with material nobody has re-authorised.
		maxAge: 7 * 24 * time.Hour,
		creds:  map[string]UpstreamCredential{},
	}
}

// Replace swaps the whole credential set.
//
// 🔴 REPLACE, not merge. The delivered set is authoritative: a credential the
// control plane stopped sending — because it was revoked — must disappear here
// on the next poll. Merging would keep a revoked secret alive in a proxy's
// memory for as long as the process ran, which is the precise opposite of what
// revocation is for.
func (s *CredentialStore) Replace(ctx context.Context, materials []Material) {
	next := make(map[string]UpstreamCredential, len(materials))
	for _, m := range materials {
		next[m.ID] = UpstreamCredential{
			Kind:       m.Kind,
			HeaderName: m.HeaderName,
			Secret:     m.Secret,
		}
	}
	s.mu.Lock()
	s.creds = next
	s.loadedAt = time.Now()
	s.mu.Unlock()

	s.writeSealedCache(ctx, materials)
}

// Resolve implements CredentialResolver.
//
// 🔴 A miss is an ERROR, never a zero-value credential. Returning an empty
// UpstreamCredential would let the caller send an unauthenticated request, and
// the resulting 401 reads to the customer as "my token is wrong" — sending them
// to rotate a credential that was never the problem.
func (s *CredentialStore) Resolve(ctx context.Context, orgID, credentialID string) (UpstreamCredential, error) {
	s.mu.RLock()
	c, ok := s.creds[credentialID]
	n := len(s.creds)
	loaded := s.loadedAt
	s.mu.RUnlock()

	if ok && c.Secret != "" {
		return c, nil
	}
	// 🔴 The log line carries the credential ID and the store's state, never
	// the secret and never the hint. "How many do we hold, and when did they
	// arrive" is what actually distinguishes the two causes an operator has to
	// tell apart: the rail never ran, or this one credential is genuinely gone.
	s.logger.WarnContext(ctx,
		"MCP backend credential could not be resolved; the tool call will be refused rather than sent unauthenticated",
		"event.name", observability.EventProxyMCPCredentialResolveFailed,
		"credential_id", credentialID,
		"org_id", orgID,
		"credentials_held", n,
		"credentials_loaded_at", loaded.Format(time.RFC3339),
	)
	return UpstreamCredential{}, fmt.Errorf("%w: credential %s is not in this proxy's store "+
		"(holding %d, last delivered %s)", ErrCredentialMissing, credentialID, n, humanAge(loaded))
}

// Count and LoadedAt feed /health/mcp.
func (s *CredentialStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.creds)
}

// LoadedAt reports when the current set arrived (zero if never).
func (s *CredentialStore) LoadedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadedAt
}

// ---------------------------------------------------------------------------
// the sealed cache
// ---------------------------------------------------------------------------

// sealedCache is the file body. Only Nonce and Ciphertext are on disk in the
// clear; everything meaningful is inside the sealed blob.
type sealedCache struct {
	WrittenAtMs int64  `json:"written_at_ms"`
	Nonce       string `json:"nonce"`
	Ciphertext  string `json:"ciphertext"`
}

func (s *CredentialStore) cachePath() string {
	if s.runDir == "" {
		return ""
	}
	return filepath.Join(s.runDir, credentialCacheFilename)
}

// writeSealedCache seals the set and writes it atomically.
//
// 🔴 Named `writeSealedCache` and not `persist` on purpose. The forwarding hot
// path fence (internal/proxy/hotpath_callgraph_fence_test.go) resolves calls by
// NAME, so a method called `persist` here joins its call graph to every other
// `persist` in the module — which made the fence report file writes in
// internal/proxy that have nothing to do with this file. An over-approximating
// fence is the right design; feeding it a colliding name for no reason is not.
func (s *CredentialStore) writeSealedCache(ctx context.Context, materials []Material) {
	path := s.cachePath()
	if path == "" {
		return
	}
	key := s.sealKey()
	if len(key) == 0 {
		if !s.warnedNoSealKey {
			s.warnedNoSealKey = true
			s.logger.WarnContext(ctx,
				"MCP credentials are held in memory only: this proxy has no vault key to seal them with, "+
					"so after a restart tool calls will fail until the next credential poll. "+
					"🚫 They are deliberately NOT written unsealed.",
				"event.name", observability.EventProxyMCPCredentialCacheUnavailable,
			)
		}
		return
	}
	plain, err := json.Marshal(materials)
	if err != nil {
		s.logger.WarnContext(ctx, "MCP credential cache could not be encoded; the restart shortcut is lost",
			"event.name", observability.EventProxyMCPCredentialCacheWriteFailed, "error", err.Error())
		return
	}
	nonce, ct, err := vault.Encrypt(key, plain)
	if err != nil {
		s.logger.WarnContext(ctx, "MCP credential cache could not be sealed; the restart shortcut is lost",
			"event.name", observability.EventProxyMCPCredentialCacheWriteFailed, "error", err.Error())
		return
	}
	body, err := json.Marshal(sealedCache{
		WrittenAtMs: time.Now().UnixMilli(),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:  base64.StdEncoding.EncodeToString(ct),
	})
	if err != nil {
		return
	}
	if err := atomicWriteFile(path, body); err != nil {
		s.logger.WarnContext(ctx, "MCP credential cache could not be written; the restart shortcut is lost",
			"event.name", observability.EventProxyMCPCredentialCacheWriteFailed,
			"path", path, "error", err.Error())
	}
}

// RestoreFromCache loads the sealed cache at boot. Returns how many credentials
// were restored.
//
// 🔴 Every failure path yields an EMPTY store, never a partial one. A partially
// restored credential set is worse than none: the backends that happen to be
// missing fail in a way that looks like a control-plane problem.
func (s *CredentialStore) RestoreFromCache(ctx context.Context) int {
	path := s.cachePath()
	key := s.sealKey()
	if path == "" || len(key) == 0 {
		return 0
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			// A missing file is the normal first-boot case (INFO-worthy at
			// most); an unreadable one is worth a WARN because it usually means
			// a permissions problem that will also break the write.
			s.logger.WarnContext(ctx, "MCP credential cache could not be read; starting empty",
				"event.name", observability.EventProxyMCPCredentialCacheReadFailed,
				"path", path, "error", err.Error())
		}
		return 0
	}
	var file sealedCache
	if err := json.Unmarshal(raw, &file); err != nil {
		s.logger.WarnContext(ctx, "MCP credential cache is not readable JSON; starting empty",
			"event.name", observability.EventProxyMCPCredentialCacheReadFailed, "path", path)
		return 0
	}
	if age := time.Since(time.UnixMilli(file.WrittenAtMs)); age > s.maxAge {
		s.logger.WarnContext(ctx,
			"MCP credential cache is too old to trust; starting empty and waiting for a fresh delivery",
			"event.name", observability.EventProxyMCPCredentialCacheExpired,
			"age_hours", int(age.Hours()), "max_age_hours", int(s.maxAge.Hours()))
		return 0
	}
	nonce, err := base64.StdEncoding.DecodeString(file.Nonce)
	if err != nil {
		return 0
	}
	ct, err := base64.StdEncoding.DecodeString(file.Ciphertext)
	if err != nil {
		return 0
	}
	plain, err := vault.Decrypt(key, nonce, ct)
	if err != nil {
		// 🔴 The usual cause is a vault re-key, and the honest answer is to
		// discard. 🚫 The error is not echoed with the file contents.
		s.logger.WarnContext(ctx,
			"MCP credential cache could not be opened with this machine's vault key "+
				"(the vault was probably re-keyed); starting empty",
			"event.name", observability.EventProxyMCPCredentialCacheReadFailed)
		return 0
	}
	var materials []Material
	if err := json.Unmarshal(plain, &materials); err != nil {
		return 0
	}
	next := make(map[string]UpstreamCredential, len(materials))
	for _, m := range materials {
		next[m.ID] = UpstreamCredential{Kind: m.Kind, HeaderName: m.HeaderName, Secret: m.Secret}
	}
	s.mu.Lock()
	s.creds = next
	s.loadedAt = time.UnixMilli(file.WrittenAtMs)
	s.mu.Unlock()
	return len(next)
}

// atomicWriteFile writes via temp+rename so a crash mid-write cannot leave a
// half file that the next boot would read as corrupt.
//
// 🔴 0600, and the temp file is created 0600 too — a 0644 temp file that exists
// for two milliseconds is still a window in which another local user can read
// every one of the customer's tool credentials.
func atomicWriteFile(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".mcp-credentials-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func humanAge(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return time.Since(t).Round(time.Second).String() + " ago"
}
