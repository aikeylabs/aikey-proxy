// Package runtime maintains the on-disk runtime snapshot of aikey-proxy.
//
// The snapshot lives at ~/.aikey/run/proxy-runtime.json and is owned by the
// proxy process itself: written after the listener binds, refreshed on
// significant lifecycle events, and removed on graceful shutdown. CLI / web
// consumers read it to discover the actually-bound port (which may differ
// from the configured port due to drift) and to learn this incarnation's pid.
//
// Why a separate file from install-state.json: install-state.json carries
// the installer-time *configured* ports (desired state); this file carries
// the *actually bound* runtime state (applied state). Mixing them violates
// the ownership rule in 20260428-proxy-状态维护统一方案.md (CLI/installer
// write desired, proxy writes applied).
//
// Schema is minimal in this commit (port-drift fields only). Future work
// (per 20260428) extends it with readiness / sync / pipeline / aggregate
// health dimensions; that work is separately scheduled and will bump
// SchemaVersion.
package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Snapshot is the on-disk runtime state.
type Snapshot struct {
	SchemaVersion int       `json:"schema_version"`
	IncarnationID string    `json:"incarnation_id"`
	PID           int       `json:"pid"`
	Listen        Listen    `json:"listen"`
	StartedAt     time.Time `json:"started_at"`
}

// Listen carries the port-drift outcome.
type Listen struct {
	ConfiguredAddr string `json:"configured_addr"`
	ActualAddr     string `json:"actual_addr"`
	DriftOffset    int    `json:"drift_offset"`
}

const (
	currentSchemaVersion = 1
	snapshotFilename     = "proxy-runtime.json"
)

// Path returns the snapshot path: $AIKEY_RUN_DIR/proxy-runtime.json if the
// env var is set (test override), else $HOME/.aikey/run/proxy-runtime.json.
func Path() (string, error) {
	if dir := os.Getenv("AIKEY_RUN_DIR"); dir != "" {
		return filepath.Join(dir, snapshotFilename), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home: %w", err)
	}
	return filepath.Join(home, ".aikey", "run", snapshotFilename), nil
}

// Write atomically persists the snapshot (temp + rename).
func Write(s Snapshot) error {
	if s.SchemaVersion == 0 {
		s.SchemaVersion = currentSchemaVersion
	}
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create run dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write tmp snapshot: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename snapshot: %w", err)
	}
	return nil
}

// Remove deletes the snapshot. Idempotent.
func Remove() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// NewIncarnationID returns a unique-ish ID for this proxy process.
func NewIncarnationID() string {
	return fmt.Sprintf("px_%d_%d", time.Now().Unix(), os.Getpid())
}
