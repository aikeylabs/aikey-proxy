package events

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// P0-4 sentSeq silent-loss fence (2026-08-19, D' auto-reconcile).
//
// The confirmed defect: uploadGroupTo treats any HTTP 200 as group-done and
// markProcessed advances sentSeq past EVERY event in the group — including
// ones the server did NOT store (per-event rejected inside a 200, or a WAL
// line skipped during a torn read). Those seqs are then filtered by
// `seq <= sentSeq` on every subsequent drain and NEVER re-sent, while the
// server's contiguous watermark stalls below them forever (2026-08-19 ladder
// forensics: worker-b contiguous=34,563 vs max_seen=50,400, unhealed at 9min).
//
// The fix (user-approved D', N=3): when sentSeq stays ahead of confirmedSeq
// for 3 consecutive un-gated drain passes with no confirmedSeq progress, the
// reporter automatically triggers the EXISTING ReconcileGaps (D3) — the
// server enumerates exactly which seqs are missing, WAL-present ones are
// re-sent (bypassing the sentSeq filter), WAL-absent ones are confirm-lost.
//
// lossyCollector below reproduces the loss shape end-to-end: it silently
// drops seq 3 on first delivery while still answering 200 with an honest
// contiguous_seq (=2). Without auto-reconcile, seq 3 is never re-sent and
// this fence times out RED.

// lossyCollector is a stateful fake collector: batch ingest stores seqs but
// DROPS dropSeq on its first delivery (still 200 + honest contiguous_seq —
// the wire carries no per-event results, exactly like the real handler).
// Serves the D3 diagnostics endpoints from its own stored-set state.
type lossyCollector struct {
	mu        sync.Mutex
	stored    map[int64]bool
	dropSeq   int64
	dropped   bool // only drop the FIRST delivery; re-sends are accepted
	gapsCalls int
	srcID     string
}

func (c *lossyCollector) contiguous() int64 {
	var n int64
	for c.stored[n+1] {
		n++
	}
	return n
}

func (c *lossyCollector) missing() []int64 {
	var out []int64
	var max int64
	for s := range c.stored {
		if s > max {
			max = s
		}
	}
	for s := int64(1); s <= max; s++ {
		if !c.stored[s] {
			out = append(out, s)
		}
	}
	return out
}

func (c *lossyCollector) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/usage-events:batch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		c.mu.Lock()
		accepted := 0
		for _, e := range req.Events {
			if e.SourceSeq == nil {
				continue
			}
			if *e.SourceSeq == c.dropSeq && !c.dropped {
				c.dropped = true // transient server-side failure: not stored, yet 200
				continue
			}
			c.stored[*e.SourceSeq] = true
			accepted++
		}
		resp := batchResponse{
			Accepted:      accepted,
			ContiguousSeq: map[string]int64{c.srcID: c.contiguous()},
		}
		c.mu.Unlock()
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/diagnostics/completeness", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sources": []map[string]any{{
				"org_id": "o", "source_id": c.srcID, "gap_count": int64(0), "tail_pending": int64(0),
			}},
		})
	})
	mux.HandleFunc("/v1/diagnostics/gaps", func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.gapsCalls++
		g := c.missing()
		c.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"missing_seqs": g, "truncated": false})
	})
	mux.HandleFunc("/v1/diagnostics/confirm-lost", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"promoted": 0, "contiguous_seq": int64(0)})
	})
	return mux
}

// TestReporter_AutoReconcile_HealsServerDroppedSeqWithoutRestart: seqs 1..6
// delivered, server silently drops 3 inside a 200. The drain loop alone can
// never recover it (sentSeq=6 filters it out); the auto-reconcile trigger
// must detect the stalled confirmed window (N=3 un-gated passes) and heal it
// via ReconcileGaps re-send — all WITHOUT a proxy restart.
func TestReporter_AutoReconcile_HealsServerDroppedSeqWithoutRestart(t *testing.T) {
	lc := &lossyCollector{stored: map[int64]bool{}, dropSeq: 3, srcID: "srcAR"}
	srv := httptest.NewServer(lc.mux())
	defer srv.Close()

	r, err := NewReporter(&ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         t.TempDir(),
		SourceID:       "srcAR",
		BatchSize:      10,
		UploadInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	for seq := int64(1); seq <= 6; seq++ {
		e := v2Event("ar-e"+string(rune('0'+seq)), "srcAR", seq)
		r.Report(&e)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		lc.mu.Lock()
		healed := len(lc.stored) == 6 && lc.stored[3]
		lc.mu.Unlock()
		if healed {
			// Recovery must have gone through the reconcile path (the drain loop
			// cannot re-send a sentSeq-filtered seq).
			lc.mu.Lock()
			calls := lc.gapsCalls
			lc.mu.Unlock()
			if calls < 1 {
				t.Fatalf("seq 3 recovered but /gaps was never called — healed by an unexpected path")
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	lc.mu.Lock()
	defer lc.mu.Unlock()
	t.Fatalf("seq 3 was never re-sent (stored=%v, /gaps calls=%d) — sentSeq permanently ahead of "+
		"confirmedSeq with no auto-reconcile; this is the P0-4 silent-loss defect", lc.stored, lc.gapsCalls)
}
