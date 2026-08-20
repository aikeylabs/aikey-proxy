package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AiKeyLabs/pkg/aikeytime"
)

// AuditStatus is the local client-side delivery state for `aikey audit status`
// (stage D2.5): the things the SERVER's completeness endpoint cannot see — this
// client's own allocator high-water, WAL backlog, dead-letter pile, and upload
// health. Read-only.
type AuditStatus struct {
	SourceID string          `json:"source_id"`
	Reporter ReporterMetrics `json:"reporter"`
	// Compliance is the team→master compliance lane's slice of the SAME
	// dead-letter queue (2026-08-10). Reported here rather than on a new
	// endpoint because this is already the one place an operator looks to ask
	// "is anything undelivered on this box?" — and until now the answer only
	// ever covered usage, so a stalled compliance pipeline was invisible.
	Compliance      ComplianceDeliveryStatus `json:"compliance"`
	AllocatedSeq    int64                    `json:"allocated_seq"`
	WALFiles        int                      `json:"wal_files"`
	DeadLetterCount int                      `json:"dead_letter_count"`
	// D' auto-reconcile visibility (P0-4): a persistently-positive
	// SentUnconfirmed with growing AutoReconcileRuns and no Resent progress is
	// the operator's cue that the collector's diagnostics endpoints are broken
	// or the gap is WAL-absent (check dead letters / known-loss).
	SentUnconfirmed     int64 `json:"sent_unconfirmed"`       // Σ max(sentSeq-confirmedSeq, 0)
	AutoReconcileRuns   int64 `json:"auto_reconcile_runs"`    // total automatic ReconcileGaps triggers
	AutoReconcileResent int64 `json:"auto_reconcile_resent"`  // total seqs recovered by auto-reconcile
	AutoReconcileGaveUp int64 `json:"auto_reconcile_gave_up"` // seqs ledgered lost after the terminal-resend budget (N4)
}

// ComplianceDeliveryStatus reports what the compliance lane has waiting and why
// it is waiting. DeadLetterEntries counts conserved BATCHES and is a subset of
// AuditStatus.DeadLetterCount (both lanes share dead_letter.jsonl);
// DeadLetterEvents counts the individual events inside them.
type ComplianceDeliveryStatus struct {
	// LastFailureReason is the last upload error verbatim (status + response
	// body excerpt). A version-skew rejection is recognizable here by the
	// master's own "unknown field" text.
	LastFailureReason string `json:"last_failure_reason,omitempty"`
	// LastFailureAt is Unix epoch milliseconds (UTC), 0 when this process has
	// never seen a compliance upload fail. Process-local, not persisted — the
	// durable record is the queue itself plus the per-entry dead_at.
	LastFailureAt     aikeytime.Millis `json:"last_failure_at,omitempty"`
	DeadLetterEntries int              `json:"dead_letter_entries"`
	DeadLetterEvents  int              `json:"dead_letter_events"`
	LastFailureCode   int              `json:"last_failure_code,omitempty"`
}

// AuditStatus gathers the local delivery state.
func (r *Reporter) AuditStatus() AuditStatus {
	st := AuditStatus{SourceID: r.cfg.SourceID, Reporter: r.Metrics()}
	if r.cfg.SeqAlloc != nil {
		st.AllocatedSeq = r.cfg.SeqAlloc.Allocated()
	}
	if r.wal != nil {
		if files, err := ListWALFiles(r.wal.Dir()); err == nil {
			st.WALFiles = len(files)
		}
	}
	if r.dlw != nil {
		c := r.dlw.counts()
		st.DeadLetterCount = c.Total
		st.Compliance.DeadLetterEntries = c.ComplianceEntries
		st.Compliance.DeadLetterEvents = c.ComplianceEvents
	}
	r.mu.RLock()
	st.Compliance.LastFailureAt = r.complianceLastFailureAt
	st.Compliance.LastFailureCode = r.complianceLastFailureCode
	st.Compliance.LastFailureReason = r.complianceLastFailureReason
	for src, sent := range r.sentSeq {
		if d := sent - r.confirmedSeq[src]; d > 0 {
			st.SentUnconfirmed += d
		}
	}
	r.mu.RUnlock()
	st.AutoReconcileRuns = r.autoReconcileRuns.Load()
	st.AutoReconcileResent = r.autoReconcileResent.Load()
	st.AutoReconcileGaveUp = r.autoReconcileGaveUp.Load()
	return st
}

// setPeriodicReconcileInterval overrides the hourly sweep cadence (tests; 0
// disables the sweep).
func (r *Reporter) setPeriodicReconcileInterval(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.periodicReconcileInterval = d
}

// ReconcileResult summarizes one client-confirmed reconciliation pass (D3).
type ReconcileResult struct {
	Sources       int `json:"sources"`        // this client's sources that had gaps
	Resent        int `json:"resent"`         // gap seqs FOUND in WAL and re-uploaded (recoverable)
	ConfirmedLost int `json:"confirmed_lost"` // gap seqs ABSENT from WAL → server-ledgered as lost now
	// GaveUp counts WAL-present seqs ledgered as lost after the terminal-resend
	// budget: DELIVERED (200) resends that the server still refused to store
	// (N4 拍板 2026-08-19 — auditable loss beats a forever-stuck watermark).
	GaveUp       int `json:"gave_up"`
	StillMissing int `json:"still_missing"` // truncated remainder (re-run reconcile to continue)
}

// terminalResendAttempts (N4 拍板 2026-08-19, K=3): a gap seq that the WAL
// holds and that has been DELIVERED (HTTP 200) this many times yet is STILL
// enumerated missing by /gaps is a terminal in-200 rejection (validation /
// content-hash-conflict class — per-event results are not on the wire, so
// delivery+still-missing is the only client-observable fingerprint). It is
// then confirm-lost like a WAL-absent seq. Network-shaped failures (dial
// error / 503 / timeout) never mark the WAL group processed, so they NEVER
// consume this budget — those retry indefinitely (拍板: 网络问题不放弃重试).
const terminalResendAttempts = 3

// ReconcileGaps performs the stage-D3 client-confirmed reconciliation: ask the
// collector which of THIS source's seqs are missing, check each against the
// local WAL, RE-SEND the ones still in the WAL (no-restart recovery), and tell
// the server to mark the ones the WAL no longer has as known-lost immediately
// (instead of waiting for the KnownLossTimeout backstop).
//
// This is an on-demand admin-triggered path — it reuses the WAL read + upload
// primitives but does NOT touch the live drainOnce loop (so the hot path is
// unchanged). Safe to call concurrently with drainOnce: the server dedups
// re-sends, and confirm-lost only ledgers genuinely-absent seqs.
func (r *Reporter) ReconcileGaps(ctx context.Context) (ReconcileResult, error) {
	var res ReconcileResult
	if r.cfg.SourceID == "" {
		return res, fmt.Errorf("source identity unknown; cannot reconcile")
	}
	bases := r.reconcileDestinations()
	if len(bases) == 0 {
		return res, fmt.Errorf("no collector destination configured; cannot reconcile")
	}
	var firstErr error
	for _, base := range bases {
		sub, err := r.reconcileAgainst(ctx, base)
		res.Sources += sub.Sources
		res.Resent += sub.Resent
		res.ConfirmedLost += sub.ConfirmedLost
		res.GaveUp += sub.GaveUp
		res.StillMissing += sub.StillMissing
		if err != nil && firstErr == nil {
			// Keep reconciling the OTHER destinations: one unreachable collector
			// must not leave a reachable one un-reconciled (that is how a single
			// offline team server froze local delivery integrity).
			firstErr = fmt.Errorf("reconcile against %s: %w", base, err)
		}
	}
	return res, firstErr
}

// reconcileDestinations lists the DISTINCT collectors this proxy uploads to.
//
// 🔴 Reconcile must ask each destination about the seqs IT was given (bugfix
// 2026-08-20). It used to ask exactly one — collectorBase(), i.e. the legacy
// single CollectorURL, which on a Personal install is the LOCAL collector —
// about every seq the source ever allocated, including the ones uploaded to the
// REMOTE team collector. The local one truthfully answered "never saw those",
// so reconcile re-sent them and then ledgered them as client-confirmed losses
// in the LOCAL ledger: 479 rows and climbing, none of them real.
//
// Cause: per-route destinations (collector_routes) landed 2026-06-13 in 212f908
// and were wired into the upload path and the dead-letter replay path, but not
// into this one — collectorBase() has not been touched since it was written on
// 2026-06-01, when one destination was the only possibility.
func (r *Reporter) reconcileDestinations() []string {
	seen := make(map[string]bool, 3)
	var out []string
	add := func(u string) {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	for _, u := range r.cfg.CollectorRoutes {
		add(u)
	}
	// Legacy single sink: also the fallback destination for any route source
	// with no entry of its own (see urlForRouteSource), so it can hold events.
	add(r.cfg.CollectorURL)
	return out
}

// reconcileAgainst runs one full reconcile pass against a single collector.
func (r *Reporter) reconcileAgainst(ctx context.Context, base string) (ReconcileResult, error) {
	var res ReconcileResult

	// Discover the (org, source) pairs for THIS source via completeness, then ask
	// /gaps for the actual missing seqs. We do NOT gate on completeness's
	// gap_count/tail_pending — those are AGE-gated (0 until a gap is stale enough
	// to alarm), but an active reconcile resolves gaps IMMEDIATELY. The /gaps
	// endpoint enumerates the genuinely-unaccounted seqs un-gated; the WAL check
	// below keeps it safe (an in-flight gap is in the WAL → re-send, not lost).
	var comp struct {
		Sources []struct {
			OrgID    string `json:"org_id"`
			SourceID string `json:"source_id"`
		} `json:"sources"`
	}
	if err := r.httpGetJSON(ctx, base+"/v1/diagnostics/completeness", &comp); err != nil {
		return res, err
	}

	for _, s := range comp.Sources {
		if s.SourceID != r.cfg.SourceID {
			continue
		}
		counted := false
		// Drain truncated gap windows: each pass re-sends / confirm-losts one
		// bounded window, which advances contiguity, so the next /gaps returns the
		// NEXT window. Bounded iterations so a pathological gap can't spin forever
		// — a leftover truncation after the cap is reported as still_missing.
		for iter := 0; iter < maxReconcileWindows; iter++ {
			var gaps struct {
				MissingSeqs []int64 `json:"missing_seqs"`
				Truncated   bool    `json:"truncated"`
			}
			gapsURL := fmt.Sprintf("%s/v1/diagnostics/gaps?org_id=%s&source_id=%s",
				base, url.QueryEscape(s.OrgID), url.QueryEscape(s.SourceID))
			if err := r.httpGetJSON(ctx, gapsURL, &gaps); err != nil {
				return res, err
			}
			if len(gaps.MissingSeqs) == 0 {
				break // converged
			}
			if !counted {
				res.Sources++
				counted = true
			}

			walSet := r.walSeqSet(s.SourceID)
			missingSet := make(map[int64]bool, len(gaps.MissingSeqs))
			for _, seq := range gaps.MissingSeqs {
				missingSet[seq] = true
			}
			var inWAL, notInWAL, gaveUp []int64
			r.mu.Lock()
			tracked := r.resendDelivered[s.SourceID]
			if tracked == nil {
				tracked = make(map[int64]int)
				r.resendDelivered[s.SourceID] = tracked
			}
			// Prune healed seqs: an entry no longer enumerated missing means the
			// delivered resend actually landed — its budget never mattered.
			for seq := range tracked {
				if !missingSet[seq] {
					delete(tracked, seq)
				}
			}
			for _, seq := range gaps.MissingSeqs {
				switch {
				case !walSet[seq]:
					notInWAL = append(notInWAL, seq)
				case tracked[seq] >= terminalResendAttempts:
					// Delivered K times, still missing: terminal rejection.
					gaveUp = append(gaveUp, seq)
				default:
					inWAL = append(inWAL, seq)
				}
			}
			r.mu.Unlock()
			// Recover WAL-present gaps by re-sending (server dedup-safe). Only
			// DELIVERED groups (200 / terminal dead-letter) consume budget —
			// retryable network failures leave the WAL untouched and uncounted.
			if len(inWAL) > 0 {
				delivered := r.resendWALSeqs(s.SourceID, inWAL)
				res.Resent += len(delivered)
				r.mu.Lock()
				for _, seq := range delivered {
					tracked[seq]++
				}
				r.mu.Unlock()
			}
			// Confirm WAL-absent gaps as lost NOW (server ledgers the genuinely-absent).
			if len(notInWAL) > 0 {
				var cl struct {
					Promoted int `json:"promoted"`
				}
				body := map[string]any{"org_id": s.OrgID, "source_id": s.SourceID, "seqs": notInWAL}
				if err := r.httpPostJSON(ctx, base+"/v1/diagnostics/confirm-lost", body, &cl); err != nil {
					return res, err
				}
				res.ConfirmedLost += cl.Promoted
			}
			// Terminal-rejected seqs: ledger as known loss (N4 拍板). LOUD by
			// design — this is billable-event loss with an audit trail, and the
			// alternative is a watermark stuck forever re-sending a copy the
			// server will never store.
			if len(gaveUp) > 0 {
				var cl struct {
					Promoted int `json:"promoted"`
				}
				body := map[string]any{"org_id": s.OrgID, "source_id": s.SourceID, "seqs": gaveUp}
				if err := r.httpPostJSON(ctx, base+"/v1/diagnostics/confirm-lost", body, &cl); err != nil {
					return res, err
				}
				res.ConfirmedLost += cl.Promoted
				res.GaveUp += len(gaveUp)
				r.autoReconcileGaveUp.Add(int64(len(gaveUp)))
				sample := gaveUp
				if len(sample) > 10 {
					sample = sample[:10]
				}
				slog.Warn("reporter: terminally rejected seqs ledgered as known loss after bounded delivered resends",
					"event.name", "usage.reporter.reconcile_gave_up",
					"source_id", s.SourceID,
					"count", len(gaveUp),
					"seqs_sample", sample,
					"delivered_attempts", terminalResendAttempts)
			}
			if !gaps.Truncated {
				break // last window for this source
			}
			if iter == maxReconcileWindows-1 {
				res.StillMissing++ // hit the cap with more to go — re-run reconcile
			}
		}
	}
	return res, nil
}

// maxReconcileWindows bounds how many truncated gap windows one reconcile pass
// drains per source (each window is up to advanceWatermarkScanLimit seqs). A
// huge gap beyond this is reported via StillMissing for a follow-up run.
const maxReconcileWindows = 100

// D' auto-reconcile tuning (P0-4 sentSeq silent-loss fix, user-approved
// 2026-08-19). sentStallReconcilePasses is the N=3 the user signed off: three
// consecutive un-gated drain passes with sentSeq ahead of confirmedSeq and
// ZERO confirmedSeq progress = a stalled window that the drain loop can never
// heal on its own. autoReconcileMinInterval debounces repeat triggers so a
// gap that reconcile cannot fix (e.g. the collector's diagnostics endpoints
// erroring) retries gently instead of hammering.
const (
	sentStallReconcilePasses = 3
	autoReconcileMinInterval = 30 * time.Second
)

// maybeAutoReconcile is called at the end of every un-gated, non-force drain
// pass. It watches the sent-but-unconfirmed window: progress on ANY source's
// confirmedSeq resets the stall counter; a fully-caught-up state resets it
// too. Only a persistent stall (sentSeq ahead + no progress for
// sentStallReconcilePasses passes) fires ReconcileGaps, asynchronously and
// singly (CAS guard), so the drain loop is never blocked.
func (r *Reporter) maybeAutoReconcile() {
	r.mu.Lock()
	stalled := false
	progressed := false
	for src, sent := range r.sentSeq {
		c := r.confirmedSeq[src]
		if c > r.lastConfirmedView[src] {
			progressed = true
		}
		r.lastConfirmedView[src] = c
		if sent > c {
			stalled = true
		}
	}
	if !stalled || progressed {
		r.stallPasses = 0
		r.mu.Unlock()
		return
	}
	r.stallPasses++
	trigger := r.stallPasses >= sentStallReconcilePasses &&
		time.Since(r.lastAutoReconcileAt) >= autoReconcileMinInterval
	// Periodic sweep (N4 拍板 2): even when the stall trigger's debounce has
	// silenced repeat fires (e.g. a gap reconcile cannot fix keeps the window
	// stalled), a sweep re-runs reconcile on its own clock so retries keep
	// happening for as long as anything is sent-but-unconfirmed.
	if !trigger && r.periodicReconcileInterval > 0 &&
		time.Since(r.lastPeriodicSweepAt) >= r.periodicReconcileInterval {
		trigger = true
	}
	if trigger {
		r.stallPasses = 0
		r.lastAutoReconcileAt = time.Now()
		r.lastPeriodicSweepAt = time.Now()
	}
	r.mu.Unlock()
	if !trigger {
		return
	}
	if !r.autoReconcileRunning.CompareAndSwap(false, true) {
		return // one reconcile at a time
	}
	go func() {
		defer r.autoReconcileRunning.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := r.ReconcileGaps(ctx)
		r.autoReconcileRuns.Add(1)
		if err != nil {
			slog.Warn("reporter: auto-reconcile failed",
				"event.name", "usage.reporter.auto_reconcile_failed", "error", err)
			return
		}
		r.autoReconcileResent.Add(int64(res.Resent))
		slog.Warn("reporter: auto-reconcile recovered a stalled sent window",
			"event.name", "usage.reporter.auto_reconcile_recovered",
			"resent", res.Resent,
			"confirmed_lost", res.ConfirmedLost,
			"gave_up", res.GaveUp,
			"still_missing", res.StillMissing)
	}()
}

// (removed 2026-08-20) collectorBase() used to resolve ONE collector base URL —
// the legacy single CollectorURL — and every reconcile/diagnostics call went
// there regardless of which collector the events had actually been uploaded to.
// It is replaced by reconcileDestinations(), which enumerates them all. Do not
// reintroduce a single-base helper here: on a Personal install CollectorURL is
// the LOCAL collector, so a single base silently reconciles TEAM deliveries
// against the PERSONAL ledger.

// walSeqSet returns the set of source_seqs present in the WAL for one source.
func (r *Reporter) walSeqSet(source string) map[int64]bool {
	set := make(map[int64]bool)
	if r.wal == nil {
		return set
	}
	entries, err := ReadAllWAL(r.wal.Dir())
	if err != nil {
		return set
	}
	for i := range entries {
		e := &entries[i]
		if e.SourceID == source && e.SourceSeq > 0 {
			set[e.SourceSeq] = true
		}
	}
	return set
}

// resendWALSeqs reads the WAL entries for the given seqs and re-uploads them via
// the normal routed upload path (uploadGroupTo advances confirmedSeq on ack).
// It deliberately bypasses the sentSeq filter — these seqs were already "sent"
// but the server never stored them, so the only way to recover without a restart
// is to push them again. Returns how many were re-uploaded.
// resendWALSeqs re-uploads the WAL entries for the given seqs and returns the
// seqs whose group was DELIVERED (uploaded 200 or terminally dead-lettered) —
// the caller's terminal-resend budget counts exactly these; retryable network
// failures return nothing and stay in the WAL for the next round.
func (r *Reporter) resendWALSeqs(source string, seqs []int64) []int64 {
	if r.wal == nil || len(seqs) == 0 {
		return nil
	}
	want := make(map[int64]bool, len(seqs))
	for _, s := range seqs {
		want[s] = true
	}
	entries, err := ReadAllWAL(r.wal.Dir())
	if err != nil {
		return nil
	}
	groups := make(map[string][]ReportableEvent)
	for i := range entries {
		e := &entries[i]
		if e.SourceID != source || e.SourceSeq <= 0 || !want[e.SourceSeq] {
			continue
		}
		want[e.SourceSeq] = false // de-dupe if a seq appears twice in the WAL
		ev := e.EventJSON
		if ev.SourceID == "" {
			ev.SourceID = e.SourceID
		}
		if ev.SourceSeq == nil {
			seq := e.SourceSeq
			ev.SourceSeq = &seq
		}
		if r.urlForEvent(&ev) == "" {
			continue // no destination for this route_source
		}
		groups[ev.RouteSource] = append(groups[ev.RouteSource], ev)
	}
	var sent []int64
	for routeSource, group := range groups {
		// Mark + count only when the group actually landed (uploaded ok or was
		// terminally dead-lettered). Advancing sentSeq here mirrors uploadPending
		// so a concurrent drainOnce doesn't re-read these seqs. A retryable
		// failure (groupRetryLater) is left un-marked: B' (缺口2) no longer
		// dead-letters retryable failures, so the seqs stay in the WAL and a
		// re-run of reconcile can recover them — `sent` stays honest.
		if r.uploadGroupTo(context.Background(), r.urlForRouteSource(routeSource), r.credentialForRouteSource(routeSource), group) == groupDone {
			r.markProcessed(group)
			for i := range group {
				if group[i].SourceSeq != nil {
					sent = append(sent, *group[i].SourceSeq)
				}
			}
		}
	}
	return sent
}

func (r *Reporter) httpGetJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := r.client.Get().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (r *Reporter) httpPostJSON(ctx context.Context, u string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Get().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST %s: status %d", u, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
