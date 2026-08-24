package events

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Characterisation, NOT a bug report: sentSeq advances when a group is HANDED
// to an upload, not when the collector confirms it. That is deliberate, and it
// is safe ONLY because of the recovery path documented beside the field
// declaration (reporter.go, "D\' auto-reconcile state"):
//
//	sentSeq may run ahead of confirmedSeq transiently; a PERSISTENT stall
//	triggers ReconcileGaps — the server enumerates the exact missing seqs and
//	WAL-present ones are re-sent, BYPASSING the sentSeq filter.
//
// 🔴 DO NOT "FIX" THIS INTO advance-on-confirm. An earlier reading of this file
// (2026-08-24) called it the cause of "usage only appears after a restart" and
// proposed exactly that change. It was wrong: the design has a bounded window
// plus a reconciler, and the reconciler is what failed in the field — see below.
//
// 🔴 WHY THE SAFETY NET DID NOT FIRE (winpc2, 2026-08-24). Three events sat
// unsent for over an hour. Auto-reconcile DID run, and reported
// resent=0 still_missing=0 — it asked the collector what was missing and was
// told "nothing". The collector believed that because its watermark had been
// pushed past those sequences by RecordKnownLoss, a consequence of the
// org-partitioned ledger (D1). A blinded reconciler cannot resend what the
// server refuses to call missing.
//
// So this test exists to pin the CONTRACT the reconciler depends on: the cursor
// advances on send, therefore recovery MUST come from reconcile. If someone
// removes or weakens auto-reconcile, this comment is the reason it cannot be.
//
// 🔴 The code says so in its own words (reporter.go, markProcessed):
//
//	"advances the in-memory cursors after a group has been handed to an upload
//	 attempt (whether it succeeded or was dead-lettered)"
//
// 🔴 FIELD EVIDENCE (winpc2, 2026-08-24). Three events sat in the WAL for over
// an hour — source_seq 2083/2084/2196, all ABOVE the collector's watermark, so
// nothing was rejecting them — while the proxy logged no upload attempts at
// all. The user's own observation is what identified this: "restart, and the
// earlier data shows up". That is the in-memory cursor being zeroed, and it is
// the only recovery path this design has.
//
// Why it matters beyond a stall: recovery-by-restart means usage silently
// depends on process lifetime. A machine that stays up simply stops reporting.
func TestAdvanceOnSend_CursorMovesOnSendSoRecoveryMustComeFromReconcile(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		// 202-with-no-verdict: the collector took the request but confirmed
		// nothing. The transport succeeded, so this is not a retryable error;
		// the batch is simply unaccounted.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":0,"duplicated":0,"quarantined":0,"rejected":0}`))
	}))
	defer srv.Close()

	r, err := NewReporter(&ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         t.TempDir(),
		SourceID:       "srcD1",
		BatchSize:      10,
		UploadInterval: time.Hour, // drive the drain by hand
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	batch := []ReportableEvent{v2Event("evA", "srcD1", 10), v2Event("evB", "srcD1", 11)}
	_ = r.uploadGroupTo(context.Background(), r.cfg.CollectorURL, nil, batch)
	r.markProcessed(batch)

	// The collector confirmed nothing, yet the cursor moved past both events.
	r.mu.RLock()
	sent := r.sentSeq["srcD1"]
	r.mu.RUnlock()

	if sent != 11 {
		t.Fatalf("sentSeq = %d, want 11 — the repro depends on the cursor advancing "+
			"on SEND. If this now fails, the fix may already be in: verify the cursor "+
			"advances on CONFIRM and delete this file.", sent)
	}

	// …and because it moved, a later pass over the same events skips them.
	skipped := 0
	for i := range batch {
		if *batch[i].SourceSeq <= sent {
			skipped++
		}
	}
	if skipped != len(batch) {
		t.Fatalf("skipped %d/%d; the repro expects every unconfirmed event to be "+
			"skipped on the next drain", skipped, len(batch))
	}

	t.Logf("characterised: %d upload(s), collector confirmed 0, cursor still advanced "+
		"to %d, so all %d events are skipped by any later drain in this process. "+
		"This is BY DESIGN — the only way back is auto-reconcile, which is why a "+
		"blinded collector watermark (D1) turns a transient miss into permanent loss.",
		hits, sent, skipped)
}
