package events

// Shutdown-bound fences (bugfix 2026-08-19-proxy-shutdown-unbounded-close).
//
// The defect: Reporter.Close / ContentReporter.Close ran an UNBOUNDED final
// flush — the whole WAL backlog, one HTTP attempt per batch, each bounded only
// by the 30s client timeout, with no early exit. Against a black-holed
// collector (TCP accepts, never answers — the exact failure shape of the ECS
// incident) a drained process sat in gen.close() until systemd's 90s SIGKILL,
// breaking rolling upgrades and the self-heal restart path.
//
// The contract these fences pin: Close returns within
// shutdownFlushBudget+closeWaitGrace (+scheduling slack) NO MATTER WHAT the
// collector does, and the attempt is real (the black-hole server observed at
// least one connection — anti-vacuity). Undelivered events are NOT lost: they
// stay in the WAL and resume after restart (also asserted).

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/aikeytime"
)

// startBlackholeCollector accepts TCP connections and never responds — the
// accept-then-hang network shape that burns the full per-attempt timeout.
// Returns the URL and a connection counter (anti-vacuity oracle).
func startBlackholeCollector(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var conns atomic.Int64
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			conns.Add(1)
			go func(c net.Conn) {
				<-hold // never answer; hold the connection open
				_ = c.Close()
			}(c)
		}
	}()
	return "http://" + ln.Addr().String(), &conns
}

func TestReporterClose_BoundedAgainstBlackholedCollector(t *testing.T) {
	url, conns := startBlackholeCollector(t)
	walDir := t.TempDir()
	reporter, err := NewReporter(&ReporterConfig{
		CollectorURL:   url,
		QueueCapacity:  100,
		WALDir:         walDir,
		BatchSize:      2,         // several batches so an unbounded flush would multiply attempts
		UploadInterval: time.Hour, // only the shutdown final flush touches the network
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		reporter.Report(&ReportableEvent{
			EventID: fmt.Sprintf("blackhole-%02d", i), OrgID: "org1",
			EventTime: aikeytime.Now(), OccurredAt: aikeytime.Now(),
			RequestStatus: "success", RequestCount: 1,
		})
	}
	// Let the async Report path land the events in the WAL before closing.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entries, _ := ReadAllWAL(walDir); len(entries) >= 10 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	start := time.Now()
	_ = reporter.Close()
	elapsed := time.Since(start)

	bound := shutdownFlushBudget + closeWaitGrace + 3*time.Second
	if elapsed > bound {
		t.Fatalf("Close took %v against a black-holed collector — exceeds the shutdown bound %v", elapsed, bound)
	}
	if conns.Load() == 0 {
		t.Fatal("black-hole collector saw no connection — the final flush never attempted an upload (vacuous fence)")
	}
	// Nothing is lost: the undelivered backlog is still in the WAL for the next
	// process to resume (crash-safe outbox is WHY the bounded flush is correct).
	entries, _ := ReadAllWAL(walDir)
	if len(entries) < 10 {
		t.Fatalf("WAL retained %d/10 entries — bounded shutdown must not drop undelivered events", len(entries))
	}
}

func TestContentReporterClose_BoundedAgainstBlackholedCollector(t *testing.T) {
	url, conns := startBlackholeCollector(t)
	wal := seedContentWAL(t, 6)
	r := NewContentReporter(&ContentReporterConfig{
		CollectorURL:    url,
		Credential:      &StaticTokenCredential{Token: "test-token"},
		ProxyInstanceID: "proxy-1",
		BatchSize:       2,
		UploadInterval:  time.Hour,
	}, wal)
	r.Start()

	start := time.Now()
	_ = r.Close()
	elapsed := time.Since(start)

	bound := shutdownFlushBudget + closeWaitGrace + 3*time.Second
	if elapsed > bound {
		t.Fatalf("content Close took %v against a black-holed collector — exceeds the shutdown bound %v", elapsed, bound)
	}
	if conns.Load() == 0 {
		t.Fatal("black-hole collector saw no connection — content final flush never attempted (vacuous fence)")
	}
}

// The periodic (non-shutdown) path must be byte-for-byte unaffected: a healthy
// collector still receives the final flush in full during Close.
func TestReporterClose_HealthyCollectorStillGetsFinalFlush(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		received.Add(int64(len(req.Events)))
		_ = json.NewEncoder(w).Encode(batchResponse{Accepted: len(req.Events)})
	}))
	defer srv.Close()
	reporter, err := NewReporter(&ReporterConfig{
		CollectorURL:   srv.URL,
		QueueCapacity:  100,
		WALDir:         t.TempDir(),
		BatchSize:      5,
		UploadInterval: time.Hour, // only the shutdown flush delivers
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		reporter.Report(&ReportableEvent{
			EventID: fmt.Sprintf("healthy-%02d", i), OrgID: "org1",
			EventTime: aikeytime.Now(), OccurredAt: aikeytime.Now(),
			RequestStatus: "success", RequestCount: 1,
		})
	}
	walDir := reporter.wal.Dir()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entries, _ := ReadAllWAL(walDir); len(entries) >= 4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = reporter.Close()
	if got := received.Load(); got != 4 {
		t.Fatalf("healthy shutdown flush delivered %d/4 events — bounding must not cost delivery on a working network", got)
	}
}
