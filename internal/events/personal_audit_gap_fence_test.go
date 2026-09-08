package events

// personal_audit_gap_fence_test.go — task 5.7.
//
// `reported_at_ms = 0` means two completely different things depending on
// whether this node follows a control plane, and the retention sweep used to
// know only one of them.
//
// bugfix: workflow/CI/bugfix/20260903-personal-audit-gap-warning-about-a-console-that-does-not-exist.md

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// oneAgedUndeliveredCall builds a store holding a single call old enough to be
// retired, which has never been delivered.
func oneAgedUndeliveredCall(t *testing.T) (*Store, RetentionConfig) {
	t.Helper()
	store := openCallStore(t)
	old := time.Now().UTC().AddDate(0, 0, -60).UnixMilli()
	if err := store.InsertMCPCall(aCall("call-aged", old)); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return store, RetentionConfig{WALDir: t.TempDir(), RetentionDays: 30, ArchiveDays: 60}
}

// sweepOnce runs exactly one retention sweep and returns what was logged.
//
// 🔴 The context is ALREADY cancelled. RetentionLoop sweeps once before it
// selects on ctx.Done(), so this drives the real loop — not a copy of its body —
// and still returns instead of waiting until midnight.
func sweepOnce(t *testing.T, cfg RetentionConfig, store *Store, hasControlPlane func() bool) string {
	t.Helper()
	var buf syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(prev)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	RetentionLoop(ctx, cfg, func() *Store { return store }, hasControlPlane)
	return buf.String()
}

// TestRetentionLoop_NoControlPlaneDoesNotClaimAnAuditGap.
//
// On a node that follows no control plane — Personal, where the local table IS
// the audit rather than an outbox — every row is undelivered forever by design.
// Retiring one on policy is not an audit gap and must not be announced as one.
//
// 🔴 The test also asserts the row was actually PRUNED. Without that half, an
// implementation that silently stopped pruning in Personal would pass: there
// would be no undelivered rows to warn about, and the disk would fill instead.
//
// 能红: in retention.go, drop the `&& delivers` term from the WARN condition.
func TestRetentionLoop_NoControlPlaneDoesNotClaimAnAuditGap(t *testing.T) {
	store, cfg := oneAgedUndeliveredCall(t)

	out := sweepOnce(t, cfg, store, func() bool { return false })

	if strings.Contains(out, observability.EventProxyMCPCallRecordDropped) {
		t.Fatalf("a node with no control plane announced an audit gap.\n"+
			"On Personal the local table is not an outbox, it IS the audit: reported_at_ms=0 is the "+
			"normal permanent state of every row, so this fires once a day forever about a console "+
			"that does not exist. A warning that is always wrong on the most common edition is how "+
			"people learn to skip the one that is right in Production.\n\nlogged:\n%s", out)
	}

	total, unreported, err := store.CountMCPCalls()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 0 || unreported != 0 {
		t.Fatalf("the aged row was not pruned (total=%d unreported=%d). Suppressing the WARNING is "+
			"the fix; suppressing the PRUNE would trade a false alarm for a full disk on an "+
			"employee laptop.", total, unreported)
	}
}

// TestRetentionLoop_AControlPlaneNodeStillReportsTheAuditGap is the control.
//
// Without it, an implementation that never warns at all would pass the test
// above — and the case this warning exists for (a Production node whose control
// plane has been unreachable for a whole retention window, so the console's call
// log really does have a permanent hole) would be silent.
//
// 能红: in retention.go, make `delivers` unconditionally false.
func TestRetentionLoop_AControlPlaneNodeStillReportsTheAuditGap(t *testing.T) {
	store, cfg := oneAgedUndeliveredCall(t)

	out := sweepOnce(t, cfg, store, func() bool { return true })

	if !strings.Contains(out, observability.EventProxyMCPCallRecordDropped) {
		t.Fatalf("a node that DOES follow a control plane retired an undelivered record without "+
			"reporting the audit gap. That is the case this warning exists for.\n\nlogged:\n%s", out)
	}
}

// TestRetentionLoop_AnUnknownDeploymentShapeWarns pins the direction of the
// default: a caller that passes nil gets the LOUD behaviour.
//
// 🔴 The quiet path has to be asked for explicitly. If nil meant "silent", then
// a future caller that forgot the argument would turn the audit-gap warning off
// for every edition, and nothing would ever report the omission.
//
// 能红: in retention.go, change the nil branch to `hasControlPlane != nil && hasControlPlane()`.
func TestRetentionLoop_AnUnknownDeploymentShapeWarns(t *testing.T) {
	store, cfg := oneAgedUndeliveredCall(t)

	out := sweepOnce(t, cfg, store, nil)

	if !strings.Contains(out, observability.EventProxyMCPCallRecordDropped) {
		t.Fatalf("a caller that did not say whether this node follows a control plane got the "+
			"SILENT behaviour. Not knowing must fail loud.\n\nlogged:\n%s", out)
	}
}
