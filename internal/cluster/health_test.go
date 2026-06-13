package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// writeVaultDirWith creates a temp "node data dir" with an optional
// daemon-status.json, returning the vault.db path inside it (the collector
// derives the status-file path from the vault path, mirroring the daemon).
func writeVaultDirWith(t *testing.T, daemonStatus string) string {
	t.Helper()
	dir := t.TempDir()
	if daemonStatus != "" {
		if err := os.WriteFile(filepath.Join(dir, daemonStatusFileName), []byte(daemonStatus), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "vault.db")
}

// TestNodeHealthSource_ForwardsDaemonFixture pins the proxy's transparency
// contract: the daemon section in the heartbeat must deep-equal the file the
// daemon wrote (no interpretation, no field drops). The fixture is a copy of
// aikey-hub/contract/daemon-status.fixture.json — see testdata/README.md.
func TestNodeHealthSource_ForwardsDaemonFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "daemon-status.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}

	vaultPath := writeVaultDirWith(t, string(raw))
	started := time.Unix(1717990005, 0)
	h := NodeHealthSource(vaultPath, "1.0.1-test", started, nil)()

	got, ok := h["daemon"].(map[string]any)
	if !ok {
		t.Fatalf("daemon section missing or wrong type: %#v", h["daemon"])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("daemon section not forwarded transparently:\n got %#v\nwant %#v", got, want)
	}

	proxy, ok := h["proxy"].(map[string]any)
	if !ok {
		t.Fatalf("proxy section missing: %#v", h)
	}
	if proxy["started_at"] != started.Unix() {
		t.Fatalf("proxy.started_at = %v, want %d", proxy["started_at"], started.Unix())
	}
	if proxy["version"] != "1.0.1-test" {
		t.Fatalf("proxy.version = %v", proxy["version"])
	}
	if nt, ok := proxy["node_time"].(int64); !ok || nt == 0 {
		t.Fatalf("proxy.node_time = %v, want non-zero int64", proxy["node_time"])
	}
}

func TestNodeHealthSource_MissingFileOmitsDaemon(t *testing.T) {
	vaultPath := writeVaultDirWith(t, "") // no status file: daemon not started yet
	h := NodeHealthSource(vaultPath, "v", time.Unix(1, 0), nil)()
	if _, present := h["daemon"]; present {
		t.Fatalf("daemon section must be absent when the status file is missing, got %#v", h["daemon"])
	}
	if _, present := h["proxy"]; !present {
		t.Fatal("proxy section must be present regardless of daemon file")
	}
}

func TestNodeHealthSource_CorruptFileOmitsDaemonWithoutPanic(t *testing.T) {
	for _, corrupt := range []string{"{half written", `"just a string"`, "[]", "null"} {
		vaultPath := writeVaultDirWith(t, corrupt)
		fn := NodeHealthSource(vaultPath, "v", time.Unix(1, 0), nil)
		h := fn()
		if _, present := h["daemon"]; present {
			t.Fatalf("daemon section must be absent for corrupt content %q", corrupt)
		}
		// Second call exercises the WARN de-duplication path (same error twice).
		_ = fn()
	}
}

// TestHeartbeatCarriesHealth asserts the wire shape: a heartbeat with a health
// source POSTs {node_id, health:{...}}, and without one stays the bare legacy
// shape — old hub + new proxy and vice versa must both keep working.
func TestHeartbeatCarriesHealth(t *testing.T) {
	var lastBody atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		lastBody.Store(m)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := NewRegistrar(srv.URL, "n1", "10.0.0.1:27200", 1, "")

	// Bare heartbeat (no health source): legacy wire shape.
	if err := r.heartbeat(context.Background()); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	bare := lastBody.Load().(map[string]any)
	if _, present := bare["health"]; present {
		t.Fatalf("bare heartbeat must not carry health: %#v", bare)
	}

	r.SetHealthSource(func() map[string]any {
		return map[string]any{"proxy": map[string]any{"version": "vX"}}
	})
	if err := r.heartbeat(context.Background()); err != nil {
		t.Fatalf("heartbeat with health: %v", err)
	}
	withHealth := lastBody.Load().(map[string]any)
	if withHealth["node_id"] != "n1" {
		t.Fatalf("node_id missing: %#v", withHealth)
	}
	health, ok := withHealth["health"].(map[string]any)
	if !ok {
		t.Fatalf("health section missing: %#v", withHealth)
	}
	proxy := health["proxy"].(map[string]any)
	if proxy["version"] != "vX" {
		t.Fatalf("health not forwarded: %#v", health)
	}
}

func TestRegisterCarriesHealth(t *testing.T) {
	var lastBody atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/register", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		lastBody.Store(m)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"registered":true,"heartbeat_interval_seconds":5}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := NewRegistrar(srv.URL, "n1", "10.0.0.1:27200", 1, "")
	r.SetHealthSource(func() map[string]any { return map[string]any{"proxy": map[string]any{}} })
	if err := r.register(context.Background()); err != nil {
		t.Fatalf("register: %v", err)
	}
	body := lastBody.Load().(map[string]any)
	if _, ok := body["health"]; !ok {
		t.Fatalf("register must carry health when a source is set: %#v", body)
	}
}

// TestNodeHealthSource_CanarySection pins the canary piggyback semantics:
// present when the getter returns a value, absent when the getter is nil OR
// returns untyped nil (probe disabled — e.g. no collector configured).
func TestNodeHealthSource_CanarySection(t *testing.T) {
	vaultPath := writeVaultDirWith(t, "")

	withCanary := NodeHealthSource(vaultPath, "v", time.Unix(1, 0), func() any {
		return map[string]any{"status": "failed", "failed_stage": "ingest", "consecutive_failures": 4}
	})()
	c, ok := withCanary["canary"].(map[string]any)
	if !ok || c["status"] != "failed" {
		t.Fatalf("canary section not forwarded: %#v", withCanary["canary"])
	}

	disabled := NodeHealthSource(vaultPath, "v", time.Unix(1, 0), func() any { return nil })()
	if _, present := disabled["canary"]; present {
		t.Fatalf("nil canary result must omit the section, got %#v", disabled["canary"])
	}
}

func TestDiskFreeMB_ReturnsValueOrUnknown(t *testing.T) {
	got := diskFreeMB(t.TempDir())
	// On unix this is a real value; the Windows stub returns -1. Either way it
	// must be sane: -1 sentinel or a non-negative MiB count.
	if got < -1 {
		t.Fatalf("diskFreeMB = %d, want >= -1", got)
	}
}
