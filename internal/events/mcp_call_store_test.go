package events

// mcp_call_store_test.go — the local call table and the outbox it doubles as.

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

func openCallStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func aCall(id string, atMs int64) mcpwire.CallRecord {
	return mcpwire.CallRecord{
		CallID: id, OrgID: "o1", SeatID: "seat-alice", ToolName: "read_file",
		AppSlug: "claude-code", Origin: mcpwire.OriginAgent,
		Status: mcpwire.CallStatusOK, ArgsDigest: "[]", CreatedAtMs: atMs,
	}
}

// TestTheLocalTableIsTheOutbox is the recovery property in one test.
//
// 🔴 A record written locally and not yet delivered must still be found by the
// next drain. That is the whole reason there is no second WAL and no
// dead-letter file for this rail: the rows themselves are the queue, so a
// control plane that is down for an hour costs a DELAY, not an audit gap, and
// the recovery needs no operator action.
func TestTheLocalTableIsTheOutbox(t *testing.T) {
	s := openCallStore(t)
	for i, id := range []string{"c1", "c2", "c3"} {
		if err := s.InsertMCPCall(aCall(id, int64(100+i))); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	batch, err := s.UnreportedMCPCalls(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 3 {
		t.Fatalf("the drain found %d undelivered records, want 3", len(batch))
	}
	// 🔴 Oldest first. A newest-first drain under a persistent backlog starves
	// the oldest rows forever — the ones an incident investigation wants most.
	if batch[0].CallID != "c1" || batch[2].CallID != "c3" {
		t.Errorf("the drain is not oldest-first: %v", []string{batch[0].CallID, batch[2].CallID})
	}

	if err := s.MarkMCPCallsReported(context.Background(), []string{"c1", "c2"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	batch, _ = s.UnreportedMCPCalls(10)
	if len(batch) != 1 || batch[0].CallID != "c3" {
		t.Fatalf("after marking two delivered the drain returned %v, want just c3", batch)
	}
	total, unreported, err := s.CountMCPCalls()
	if err != nil {
		t.Fatal(err)
	}
	// 🔴 Delivered rows STAY. They are the local record — the only record on
	// Personal, where there is no control plane to ship to at all.
	if total != 3 || unreported != 1 {
		t.Errorf("total=%d unreported=%d, want 3 and 1. Deleting on delivery would leave "+
			"Personal edition with no call log at all.", total, unreported)
	}
}

// TestArgsRawIsNullByDefaultLocally is fence 7.F1's local half.
func TestArgsRawIsNullByDefaultLocally(t *testing.T) {
	s := openCallStore(t)
	if err := s.InsertMCPCall(aCall("c1", 1)); err != nil {
		t.Fatal(err)
	}
	var raw *string
	if err := s.db.QueryRow(`SELECT args_raw FROM mcp_call_event WHERE call_id='c1'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		t.Errorf("args_raw stored %q for a record that supplied none; the default must be SQL NULL "+
			"so 'withheld' stays distinguishable from 'empty'", *raw)
	}
	// And a supplied empty string must round-trip as a VALUE, not as NULL.
	empty := ""
	rec := aCall("c2", 2)
	rec.ArgsRaw = &empty
	if err := s.InsertMCPCall(rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.UnreportedMCPCalls(10)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.CallID == "c2" && r.ArgsRaw == nil {
			t.Error("an explicitly-empty args_raw came back as NULL; retention-on-but-empty and " +
				"retention-off would then be the same row")
		}
	}
}

// TestARepeatedCallIDIsReportedNotSwallowed — the asymmetry with the control
// plane, and the reason it is deliberate.
//
// 🔴 There, ON CONFLICT DO NOTHING is the idempotency that makes at-least-once
// delivery safe. HERE, a duplicate can only come from a bug in the recorder, so
// swallowing it would hide the bug.
func TestARepeatedCallIDIsReportedNotSwallowed(t *testing.T) {
	s := openCallStore(t)
	if err := s.InsertMCPCall(aCall("c1", 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertMCPCall(aCall("c1", 2)); err == nil {
		t.Error("a duplicate call_id was accepted silently. Locally that can only mean the recorder " +
			"recorded one call twice, and a silent success would hide it.")
	}
}

// TestRetentionCountsWhatItThrowsAway is the audit-gap number.
//
// 🔴 Deleting an undelivered record makes a gap in the console's call log
// permanent. That is an accepted trade (a full disk on an employee laptop
// breaks the user's main path; a delayed audit record does not) — but it must
// be a NUMBER somebody can see, not something that quietly did not happen.
func TestRetentionCountsWhatItThrowsAway(t *testing.T) {
	s := openCallStore(t)
	old := time.Now().Add(-48 * time.Hour)
	delivered := aCall("c-old-delivered", old.UnixMilli())
	undelivered := aCall("c-old-undelivered", old.UnixMilli())
	fresh := aCall("c-fresh", time.Now().UnixMilli())
	for _, r := range []mcpwire.CallRecord{delivered, undelivered, fresh} {
		if err := s.InsertMCPCall(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MarkMCPCallsReported(context.Background(), []string{"c-old-delivered"}, time.Now()); err != nil {
		t.Fatal(err)
	}

	pruned, gap, err := s.PruneMCPCallsOlderThan(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 2 {
		t.Errorf("pruned %d rows, want 2", pruned)
	}
	if gap != 1 {
		t.Errorf("the sweep reported %d undelivered records deleted, want 1. Without that number, "+
			"a permanent hole in the audit trail is invisible.", gap)
	}
	total, _, _ := s.CountMCPCalls()
	if total != 1 {
		t.Errorf("%d rows survived the sweep, want 1 (the fresh one)", total)
	}
}

// TestTheRecorderReportsADropRatherThanSwallowingIt — the sink has no error
// return by design (a tool call must not fail because our audit write failed),
// so this WARN plus its counter is the ONLY way a lost record is noticed.
func TestTheRecorderReportsADropRatherThanSwallowingIt(t *testing.T) {
	dropped := 0
	rec := NewMCPCallRecorder(func() *Store { return nil }, slog.Default(), func() { dropped++ })
	rec.RecordCall(context.Background(), aCall("c1", 1))
	if dropped != 1 {
		t.Errorf("a record with nowhere to go was dropped %d times by the counter, want 1. The "+
			"counter is the only signal: the sink cannot return an error without making a tool "+
			"call fail on an audit-write failure.", dropped)
	}
	if backlog, known := rec.CallBacklog(); known {
		t.Errorf("a recorder with no store reported a backlog of %d as KNOWN; zero would read as "+
			"'everything is delivered', the opposite of what a missing store means", backlog)
	}
}
