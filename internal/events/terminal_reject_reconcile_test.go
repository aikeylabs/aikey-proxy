package events

// N4 fences (2026-08-19 拍板): the reconcile loop must distinguish TERMINAL
// in-200 rejections from network failures.
//
//  1. A seq the server keeps refusing to store while answering 200 (validation
//     / content-hash-conflict class) previously livelocked forever: /gaps named
//     it every round, the WAL had it, resendWALSeqs re-delivered it, the server
//     dropped it again — contiguous stuck for the whole 300s ladder window.
//     拍板: after K=3 DELIVERED-yet-still-missing resends, ledger it as known
//     loss (auditable loss beats a forever-stuck watermark, D1 philosophy).
//  2. Network-shaped failures (dial error / 503 / timeout) must NEVER consume
//     the K budget — the proxy retries those indefinitely (拍板: 网络问题不放弃).
//  3. A periodic sweep (default hourly, riding the existing drain tick — no new
//     timer goroutine) must re-run reconcile even after the stall trigger's
//     debounce has silenced it (拍板: 定期重试上传机制).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// terminalCollector: always refuses to store rejectSeq while answering 200
// with honest contiguous (the terminal in-200 shape). Optional knobs:
// resend503Budget answers whole-batch 503 for the first N deliveries that
// contain rejectSeq (network-shaped phase); confirmLostNoop makes
// /confirm-lost a no-op so the gap never converges (periodic-sweep fence).
type terminalCollector struct {
	mu              sync.Mutex
	stored          map[int64]bool
	lost            map[int64]bool
	rejectSeq       int64
	resend503Budget int
	confirmLostNoop bool
	srcID           string

	rejectDeliveries int // 200-delivered batches that carried rejectSeq
	gapsCalls        int
	confirmLostSeqs  []int64 // every seq ever posted to /confirm-lost
}

func (c *terminalCollector) contiguous() int64 {
	var n int64
	for c.stored[n+1] || c.lost[n+1] {
		n++
	}
	return n
}

func (c *terminalCollector) missing() []int64 {
	var out []int64
	var max int64
	for s := range c.stored {
		if s > max {
			max = s
		}
	}
	for s := int64(1); s <= max; s++ {
		if !c.stored[s] && !c.lost[s] {
			out = append(out, s)
		}
	}
	return out
}

func (c *terminalCollector) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/usage-events:batch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		c.mu.Lock()
		defer c.mu.Unlock()
		carriesReject := false
		for _, e := range req.Events {
			if e.SourceSeq != nil && *e.SourceSeq == c.rejectSeq {
				carriesReject = true
			}
		}
		if carriesReject && len(req.Events) == 1 && c.resend503Budget > 0 {
			// Network-shaped failure on a RESEND delivery (reconcile resends
			// carry only the missing seq): whole batch refused, nothing stored.
			// Scoped to resends so the original 6-event upload sails through —
			// a 503 there would only exercise the already-fenced drain backoff.
			c.resend503Budget--
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "INGEST_TRANSIENT_FAILURE"})
			return
		}
		accepted := 0
		for _, e := range req.Events {
			if e.SourceSeq == nil {
				continue
			}
			if *e.SourceSeq == c.rejectSeq {
				continue // terminal in-200 rejection: 200, honest contiguous, never stored
			}
			c.stored[*e.SourceSeq] = true
			accepted++
		}
		if carriesReject {
			c.rejectDeliveries++
		}
		_ = json.NewEncoder(w).Encode(batchResponse{
			Accepted:      accepted,
			ContiguousSeq: map[string]int64{c.srcID: c.contiguous()},
		})
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
		var body struct {
			Seqs []int64 `json:"seqs"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		c.mu.Lock()
		c.confirmLostSeqs = append(c.confirmLostSeqs, body.Seqs...)
		promoted := 0
		if !c.confirmLostNoop {
			for _, s := range body.Seqs {
				if !c.lost[s] {
					c.lost[s] = true
					promoted++
				}
			}
		}
		c.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"promoted": promoted})
	})
	return mux
}

func (c *terminalCollector) snapshot() (rejectDeliveries, gapsCalls int, lostSeqs []int64, cont int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rejectDeliveries, c.gapsCalls, append([]int64(nil), c.confirmLostSeqs...), c.contiguous()
}

func newTerminalReporter(t *testing.T, srvURL, src string) *Reporter {
	t.Helper()
	r, err := NewReporter(&ReporterConfig{
		CollectorURL:   srvURL,
		WALDir:         t.TempDir(),
		SourceID:       src,
		BatchSize:      10,
		UploadInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Fence 1+2: a terminally rejected seq must be ledgered as known loss after
// EXACTLY K delivered rejections — and 503-shaped (network) failures must not
// consume the budget. Pre-fix this livelocks: /confirm-lost is never called
// for a WAL-present seq and the fence times out RED.
func TestReporter_TerminalRejectLedgeredAfterBoundedDeliveredResends(t *testing.T) {
	tc := &terminalCollector{
		stored: map[int64]bool{}, lost: map[int64]bool{},
		rejectSeq: 3, srcID: "srcTR",
		// First two resend deliveries answer 503 (network shape) — they must
		// NOT count toward the K=3 terminal budget.
		resend503Budget: 2,
	}
	srv := httptest.NewServer(tc.mux())
	defer srv.Close()
	r := newTerminalReporter(t, srv.URL, "srcTR")
	defer r.Close()
	// One reconcile run handles ONE gap window; consecutive runs are what walk
	// the budget. Production paces them via the stall trigger (30s debounce) +
	// the hourly sweep; the test paces via a fast sweep.
	r.setPeriodicReconcileInterval(250 * time.Millisecond)

	for seq := int64(1); seq <= 6; seq++ {
		e := v2Event("tr-e"+string(rune('0'+seq)), "srcTR", seq)
		r.Report(&e)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, _, lostSeqs, cont := tc.snapshot()
		for _, s := range lostSeqs {
			if s == 3 && cont == 6 {
				// Converged: ledgered as lost, watermark past it. The budget
				// must have been consumed by DELIVERED rejections only.
				rejectDeliveries, _, _, _ := tc.snapshot()
				// Exactly 1 original delivery + K resend deliveries; the two
				// 503-phase attempts were refused whole-batch and must not have
				// consumed the terminal budget.
				if rejectDeliveries < 1+terminalResendAttempts {
					t.Fatalf("gave up after only %d delivered rejections (want ≥%d incl. the original) — "+
						"network-shaped failures must not consume the terminal budget",
						rejectDeliveries, 1+terminalResendAttempts)
				}
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	rejectDeliveries, gapsCalls, lostSeqs, cont := tc.snapshot()
	t.Fatalf("terminally rejected seq 3 never ledgered as known loss "+
		"(delivered rejections=%d, /gaps calls=%d, confirm-lost=%v, contiguous=%d) — "+
		"the reconcile loop is livelocked re-sending a seq the server will never store",
		rejectDeliveries, gapsCalls, lostSeqs, cont)
}

// Fence 3: the periodic sweep must keep re-running reconcile after the stall
// trigger's 30s debounce has silenced it. confirmLostNoop keeps the gap alive
// forever; only the periodic leg can produce repeated /gaps calls inside the
// debounce window. Also pins that a given-up seq stops being re-sent (the
// delivered-rejection count stays at the budget while sweeps continue).
func TestReporter_PeriodicSweepRefiresWithinStallDebounce(t *testing.T) {
	tc := &terminalCollector{
		stored: map[int64]bool{}, lost: map[int64]bool{},
		rejectSeq: 3, srcID: "srcPS", confirmLostNoop: true,
	}
	srv := httptest.NewServer(tc.mux())
	defer srv.Close()
	r := newTerminalReporter(t, srv.URL, "srcPS")
	defer r.Close()
	r.setPeriodicReconcileInterval(250 * time.Millisecond)

	for seq := int64(1); seq <= 6; seq++ {
		e := v2Event("ps-e"+string(rune('0'+seq)), "srcPS", seq)
		r.Report(&e)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, gapsCalls, _, _ := tc.snapshot()
		if gapsCalls >= 3 {
			// ≥3 reconcile rounds inside 15s: the stall trigger alone can fire
			// at most once per 30s debounce — the extra rounds are the sweep.
			rejectDeliveries, _, _, _ := tc.snapshot()
			// 1 original delivery + at most K resends; further sweeps must NOT
			// keep re-sending a given-up seq.
			if rejectDeliveries > 1+terminalResendAttempts {
				t.Fatalf("given-up seq was delivered %d times (budget 1+%d) — give-up must stop resends",
					rejectDeliveries, terminalResendAttempts)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, gapsCalls, _, _ := tc.snapshot()
	t.Fatalf("only %d /gaps calls in 15s — no periodic sweep (stall debounce silences repeat fires for 30s)", gapsCalls)
}
