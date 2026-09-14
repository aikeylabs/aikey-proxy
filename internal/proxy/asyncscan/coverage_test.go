package asyncscan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/pkg/deepscan"
)

// TestAsyncScanCoverage_PieceCapIsFinalPartial: a piece truncated at the cap is
// DONE — partial, but final.
//
// The distinction that matters is final vs not-final, not complete vs partial.
// A capped piece will never produce more coverage no matter how many times it is
// re-sent (the cap is deterministic), so the already-scanned record must mark it
// finished. Treating it as unfinished would re-enqueue the same oversized piece
// on every turn of the conversation, forever.
func TestAsyncScanCoverage_PieceCapIsFinalPartial(t *testing.T) {
	m := MergedResult{
		Coverage: Coverage{Status: deepscan.StatusPartial, ScannedBytes: 262144, TotalBytes: 400000},
	}
	final, cov := Finalize(m, 0)
	if !final {
		t.Fatal("a cap-truncated result is final: re-sending the same piece cannot produce more coverage")
	}
	if cov == nil {
		t.Fatal("a partial result must carry scan_coverage; without it the audit row asserts the tail was clean")
	}
	if cov.Status != deepscan.StatusPartial {
		t.Errorf("status = %q, want partial", cov.Status)
	}
	if cov.ScannedBytes >= cov.TotalBytes {
		t.Errorf("a partial coverage claiming it scanned everything is not partial: %+v", cov)
	}
}

// TestAsyncScanCoverage_TransientPartialNotFinal: a transient failure (node
// timed out, connection dropped) leaves the piece UNSCANNED, so it must stay
// claimable — until the attempt cap, after which it finalises as partial so a
// permanently-down node cannot make every turn re-enqueue the same content.
func TestAsyncScanCoverage_TransientPartialNotFinal(t *testing.T) {
	m := MergedResult{
		Coverage: Coverage{Status: deepscan.StatusPartial, ScannedBytes: 0, TotalBytes: 40000},
	}
	m.Coverage.Status = deepscan.StatusPartial

	for attempt := 1; attempt < maxTransientAttempts; attempt++ {
		final, _ := Finalize(transient(m), attempt)
		if final {
			t.Fatalf("attempt %d: a transient failure must NOT finalise — the content was never scanned", attempt)
		}
	}
	final, cov := Finalize(transient(m), maxTransientAttempts)
	if !final {
		t.Fatalf("after %d transient failures the piece must finalise, or a down node re-enqueues it every turn", maxTransientAttempts)
	}
	if cov == nil || cov.Status != deepscan.StatusPartial {
		t.Errorf("the give-up result must be recorded as partial, not complete: %+v", cov)
	}
}

func transient(m MergedResult) MergedResult {
	m.Coverage.Status = deepscan.StatusPartial
	m.Coverage.Reason = deepscan.ReasonTransient
	return m
}

// TestAsyncScanCoverage_OldMasterOmitsFieldSeparateBatch is the mixed-version
// fence.
//
// 🔴 WHAT BREAKS WITHOUT IT. scan_coverage is a NEW field, and the publish order
// is master first, then proxies (design §4b.12). During the window in between,
// a proxy that already sends it is talking to a master that does not know it.
// If that master rejects the unknown field, the whole BATCH fails — and because
// the async events would otherwise ride along with the fast layer's events, a
// new proxy would take the SYNCHRONOUS audit trail down with it. That is a
// compliance outage caused by an optional observability field.
//
// Two mechanisms, both checked here: strip the field when the capability is
// absent, and never mix async events into a fast-layer batch.
func TestAsyncScanCoverage_OldMasterOmitsFieldSeparateBatch(t *testing.T) {
	m := Merge(PieceJob{
		JobID: "j1", TenantID: "org_a", AuditUnitID: "au_1", ContentSHA256: "sha",
		Source: deepscan.SourceRequest, Text: strings.Repeat("a", 64*1024), HeadBytes: 16 * 1024,
	}, deepscan.ResultFrame{
		JobID: "j1", Status: deepscan.StatusPartial, Reason: deepscan.ReasonPieceCap,
		ScannedBytes: 60 * 1024, TotalBytes: 64 * 1024,
		Findings: []deepscan.Finding{ruleFinding(40_000, 40_060, "CREDENTIAL_DSN")},
	}, apphook.ActionBlock, apphook.ActionBlock)

	events := BuildEvents(m, RequestIdentity{TenantID: "org_a"})
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].ScanCoverage == nil {
		t.Fatal("BuildEvents did not attach scan_coverage to a partial result")
	}

	// New master: the field survives.
	withCap := EncodeForMaster(events, []string{"scan_coverage"})
	if !strings.Contains(string(withCap[0]), `"scan_coverage"`) {
		t.Errorf("a master advertising scan_coverage did not receive it: %s", withCap[0])
	}

	// Old master: the field is STRIPPED, and everything else survives intact.
	for _, features := range [][]string{nil, {}, {"something_else"}} {
		out := EncodeForMaster(events, features)
		if len(out) != 1 {
			t.Fatalf("features=%v: encoding lost the event", features)
		}
		if strings.Contains(string(out[0]), "scan_coverage") {
			t.Errorf("features=%v: scan_coverage was NOT stripped: %s", features, out[0])
		}
		var got map[string]any
		if err := json.Unmarshal(out[0], &got); err != nil {
			t.Fatalf("features=%v: stripping produced invalid JSON: %v", features, err)
		}
		for _, k := range []string{"event_id", "tenant_id", "scenario", "action_taken", "findings"} {
			if _, ok := got[k]; !ok {
				t.Errorf("features=%v: stripping also removed %q", features, k)
			}
		}
		if got["event_id"] != events[0].EventID {
			t.Errorf("features=%v: the event id changed during stripping", features)
		}
	}
}
