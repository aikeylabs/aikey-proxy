// group_login_state.go — bypass "member login required" state file.
//
// Why a SEPARATE file instead of extending ~/.aikey/run/proxy-runtime.json:
// the runtime snapshot is rewritten wholesale by the supervisor on lifecycle
// events; this state is written from the REQUEST path. Sharing one file would
// force read-modify-write locking across owners (last-writer-wins would drop
// fields). One concern, one file, one writer — same ownership rule as
// 20260428-proxy-状态维护统一方案.md.
//
// Why a file at all (vs usage-WAL event or an HTTP status endpoint): the CLI
// statusline is offline-by-design (reads local files only, zero RPC), and the
// usage pipeline is the revenue-critical main path — a bypass display concern
// must not add events to it. See
// update/20260703-OAuth组成员登录提示-CLI显示与login_url.md 决策3.
//
// Consumers: `aikey statusline` renders "login required → <url>" while this
// file exists. The proxy clears it on the next successful group-credential
// resolve (the member completed login), so statusline recovery is automatic.
package proxy

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

const groupLoginStateFilename = "group-login-required.json"

// groupLoginState mirrors the JSON shape read by aikey-cli statusline. Field
// changes are a cross-repo contract — update commands_statusline.rs together.
type groupLoginStateBody struct {
	Provider  string `json:"provider"`
	AccountID string `json:"account_id"`
	LoginURL  string `json:"login_url"`
	// WrittenAt lets readers ignore stale files (e.g. proxy crashed before
	// clearing). Unix millis, matching the usage-WAL event_time convention.
	WrittenAt int64 `json:"written_at"`
}

// groupLoginStateStore is always non-nil on a Proxy (set in New). `dirty`
// starts true so the FIRST successful group resolve after process start
// removes any file left behind by a previous incarnation (login may have
// completed while the proxy was down); afterwards Clear() is a no-op until
// the next Write, keeping the group-route hot path syscall-free.
type groupLoginStateStore struct {
	dirty atomic.Bool
}

func newGroupLoginStateStore() *groupLoginStateStore {
	s := &groupLoginStateStore{}
	s.dirty.Store(true)
	return s
}

// path mirrors runtime.Path(): $AIKEY_RUN_DIR override for tests, else
// ~/.aikey/run/.
func (s *groupLoginStateStore) path() (string, error) {
	if dir := os.Getenv("AIKEY_RUN_DIR"); dir != "" {
		return filepath.Join(dir, groupLoginStateFilename), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aikey", "run", groupLoginStateFilename), nil
}

// Write persists the login-required state (temp + rename, atomic for readers).
// Best-effort: a failure must never turn the structured 401 into a 500, but it
// is WARN-logged — a silently missing statusline hint is a debugging trap.
func (s *groupLoginStateStore) Write(logger *slog.Logger, provider, accountID, loginURL string) {
	path, err := s.path()
	if err == nil {
		err = func() error {
			if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
				return mkErr
			}
			data, mErr := json.Marshal(groupLoginStateBody{
				Provider:  provider,
				AccountID: accountID,
				LoginURL:  loginURL,
				WrittenAt: time.Now().UnixMilli(),
			})
			if mErr != nil {
				return mErr
			}
			tmp := path + ".tmp"
			if wErr := os.WriteFile(tmp, data, 0o600); wErr != nil {
				return wErr
			}
			return os.Rename(tmp, path)
		}()
	}
	if err != nil {
		logger.Warn("group login state: write failed — statusline will not show the login hint",
			"event.name", observability.EventProxyGroupLoginStateWriteFailed,
			"error", err)
		return
	}
	s.dirty.Store(true)
}

// Clear removes the state file after a successful group resolve. Cheap when
// nothing was written (atomic load, no syscall). Removal failure is WARN-worthy
// too: a stale file makes statusline nag about a login that already happened.
func (s *groupLoginStateStore) Clear(logger *slog.Logger) {
	if !s.dirty.Load() {
		return
	}
	path, err := s.path()
	if err == nil {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			err = rmErr
		}
	}
	if err != nil {
		logger.Warn("group login state: clear failed — statusline may show a stale login hint",
			"event.name", observability.EventProxyGroupLoginStateClearFailed,
			"error", err)
		return
	}
	s.dirty.Store(false)
}
