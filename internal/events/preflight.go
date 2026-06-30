package events

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
)

// PreflightResult holds the outcome of usage pipeline readiness checks.
// Preflight runs once at proxy startup and never blocks serving — it only
// logs warnings and sets status flags for /status consumption.
type PreflightResult struct {
	Errors             []string `json:"errors,omitempty"`
	CollectorReachable bool     `json:"collector_reachable"`
	CollectorAuthOK    bool     `json:"collector_auth_ok"`
	WALWritable        bool     `json:"wal_writable"`
	EventsDBReady      bool     `json:"events_db_ready"`
}

// OK returns true if all checks passed.
func (r PreflightResult) OK() bool {
	return len(r.Errors) == 0
}

// RunPreflight verifies the usage pipeline is ready before serving requests.
// It checks collector reachability, auth token validity, WAL writability,
// and events DB accessibility. Never blocks startup — only logs and returns results.
func RunPreflight(collectorURL, collectorToken, walDir, eventsDBPath string) PreflightResult {
	result := PreflightResult{
		CollectorReachable: true,
		CollectorAuthOK:    true,
		WALWritable:        true,
		EventsDBReady:      true,
	}

	// 1. Collector reachability + auth (skip if no collector configured)
	if collectorURL != "" {
		reachable, authOK, err := checkCollector(collectorURL, collectorToken)
		result.CollectorReachable = reachable
		result.CollectorAuthOK = authOK
		if err != "" {
			result.Errors = append(result.Errors, err)
		}
	}

	// 2. WAL directory writable
	if walDir != "" {
		if err := checkWALDir(walDir); err != nil {
			result.WALWritable = false
			result.Errors = append(result.Errors, err.Error())
		}
	}

	// 3. Events DB accessible
	if eventsDBPath != "" {
		if err := checkEventsDB(eventsDBPath); err != nil {
			result.EventsDBReady = false
			result.Errors = append(result.Errors, err.Error())
		}
	}

	// Log result
	if result.OK() {
		slog.Info("usage pipeline preflight OK")
	} else {
		for _, e := range result.Errors {
			slog.Warn("usage pipeline preflight FAILED", "issue", e)
		}
	}

	return result
}

// checkCollector tests collector reachability and token auth by sending an empty batch.
func checkCollector(collectorURL, token string) (reachable, authOK bool, errMsg string) {
	client := httpx.NewDirectClient(5 * time.Second)
	url := collectorURL + "/v1/usage-events:batch"
	body := []byte(`{"source":"preflight","events":[]}`)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, false, fmt.Sprintf("collector: build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, false, fmt.Sprintf("collector unreachable at %s: %v", collectorURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return true, false, fmt.Sprintf("collector auth failed (HTTP %d): collector_token may not match service_token", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return true, true, fmt.Sprintf("collector returned HTTP %d (may be normal for empty batch)", resp.StatusCode)
	}

	return true, true, ""
}

// checkWALDir verifies the WAL directory exists and is writable.
func checkWALDir(dir string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return fmt.Errorf("WAL dir does not exist: %s", dir)
	}
	if err != nil {
		return fmt.Errorf("WAL dir stat failed: %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("WAL path is not a directory: %s", dir)
	}
	// Test writability by creating and removing a temp file
	tmp := dir + "/.preflight_test"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("WAL dir not writable: %s: %w", dir, err)
	}
	f.Close()
	os.Remove(tmp)
	return nil
}

// checkEventsDB verifies the events DB file exists and is accessible.
func checkEventsDB(dbPath string) error {
	_, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("events DB not found: %s", dbPath)
	}
	if err != nil {
		return fmt.Errorf("events DB stat failed: %s: %w", dbPath, err)
	}
	return nil
}
