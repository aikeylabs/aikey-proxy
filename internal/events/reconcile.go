package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// AuditStatus is the local client-side delivery state for `aikey audit status`
// (stage D2.5): the things the SERVER's completeness endpoint cannot see — this
// client's own allocator high-water, WAL backlog, dead-letter pile, and upload
// health. Read-only.
type AuditStatus struct {
	SourceID        string          `json:"source_id"`
	Reporter        ReporterMetrics `json:"reporter"`
	AllocatedSeq    int64           `json:"allocated_seq"`
	WALFiles        int             `json:"wal_files"`
	DeadLetterCount int             `json:"dead_letter_count"`
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
		st.DeadLetterCount = r.dlw.Count()
	}
	return st
}

// ReconcileResult summarizes one client-confirmed reconciliation pass (D3).
type ReconcileResult struct {
	Sources       int `json:"sources"`        // this client's sources that had gaps
	Resent        int `json:"resent"`         // gap seqs FOUND in WAL and re-uploaded (recoverable)
	ConfirmedLost int `json:"confirmed_lost"` // gap seqs ABSENT from WAL → server-ledgered as lost now
	StillMissing  int `json:"still_missing"`  // truncated remainder (re-run reconcile to continue)
}

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
	base := r.collectorBase()
	if base == "" {
		return res, fmt.Errorf("no collector_url configured; cannot reconcile")
	}
	if r.cfg.SourceID == "" {
		return res, fmt.Errorf("source identity unknown; cannot reconcile")
	}

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
			var inWAL, notInWAL []int64
			for _, seq := range gaps.MissingSeqs {
				if walSet[seq] {
					inWAL = append(inWAL, seq)
				} else {
					notInWAL = append(notInWAL, seq)
				}
			}
			// Recover WAL-present gaps by re-sending (server dedup-safe).
			if len(inWAL) > 0 {
				res.Resent += r.resendWALSeqs(s.SourceID, inWAL)
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

// collectorBase resolves the collector base URL (legacy single URL, else the
// first non-empty per-route URL). The reconcile endpoints live on the collector.
func (r *Reporter) collectorBase() string {
	if r.cfg.CollectorURL != "" {
		return strings.TrimRight(r.cfg.CollectorURL, "/")
	}
	for _, u := range r.cfg.CollectorRoutes {
		if u != "" {
			return strings.TrimRight(u, "/")
		}
	}
	return ""
}

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
func (r *Reporter) resendWALSeqs(source string, seqs []int64) int {
	if r.wal == nil || len(seqs) == 0 {
		return 0
	}
	want := make(map[int64]bool, len(seqs))
	for _, s := range seqs {
		want[s] = true
	}
	entries, err := ReadAllWAL(r.wal.Dir())
	if err != nil {
		return 0
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
	sent := 0
	for routeSource, group := range groups {
		// Mark + count only when the group actually landed (uploaded ok or was
		// terminally dead-lettered). Advancing sentSeq here mirrors uploadPending
		// so a concurrent drainOnce doesn't re-read these seqs. A retryable
		// failure (groupRetryLater) is left un-marked: B' (缺口2) no longer
		// dead-letters retryable failures, so the seqs stay in the WAL and a
		// re-run of reconcile can recover them — `sent` stays honest.
		if r.uploadGroupTo(r.urlForRouteSource(routeSource), r.credentialForRouteSource(routeSource), group) == groupDone {
			r.markProcessed(group)
			sent += len(group)
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
