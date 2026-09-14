package asyncscan

import (
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/deepscan"
	"github.com/AiKeyLabs/pkg/scanchunk"
)

// TestAsyncScanPlacement_PersonalPieceNeverLeavesMachine is the hardest rule in
// this package, and the only one with no exceptions.
//
// 🔴 A personal-routed piece is an individual's own content on their own machine,
// scanned for their own self-view. It has no organisation behind it, no tenant to
// authorize a node against, and nobody who consented to it being sent anywhere.
// So it is scanned HERE or not at all — regardless of how many nodes are
// configured, regardless of what the org policy says, regardless of edition.
// spec: R-scan-node-deepscan-16.S1
//
// The loop is exhaustive on purpose: the failure mode this guards is someone
// adding a branch ("...unless the org forces it") that only fires in one
// combination.
func TestAsyncScanPlacement_PersonalPieceNeverLeavesMachine(t *testing.T) {
	personal := CommittedPiece{Text: "my own notes", Personal: true}
	for _, ts := range []TeamAsyncScan{TeamAsyncScanNodes, TeamAsyncScanLocal, TeamAsyncScanOff, TeamAsyncScan("garbage"), ""} {
		for _, clusterNodes := range []bool{true, false} {
			got := Place(personal, ts, clusterNodes)
			if got == PlacementRemote {
				t.Errorf("personal piece placed REMOTE with team_async_scan=%q clusterNodes=%v — "+
					"an individual's own content would leave their machine", ts, clusterNodes)
			}
			if got != PlacementLocal {
				t.Errorf("personal piece placed %q with team_async_scan=%q clusterNodes=%v; want %q",
					got, ts, clusterNodes, PlacementLocal)
			}
		}
	}
}

// TestAsyncScanPlacement_TrialTeamPieceRunsLocally: Trial has no scan nodes, so a
// TEAM piece there is scanned on the machine rather than skipped. Skipping would
// mean a Trial customer silently gets no asynchronous coverage at all while the
// health page says the lane is fine.
func TestAsyncScanPlacement_TrialTeamPieceRunsLocally(t *testing.T) {
	team := CommittedPiece{Text: "quarterly numbers", Personal: false}

	if got := Place(team, TeamAsyncScanLocal, false); got != PlacementLocal {
		t.Errorf("Trial team piece placed %q, want %q", got, PlacementLocal)
	}
	// Production with nodes advertised → remote.
	if got := Place(team, TeamAsyncScanNodes, false); got != PlacementRemote {
		t.Errorf("team piece with team_async_scan=nodes placed %q, want %q", got, PlacementRemote)
	}
	// Cluster: the rendered node list wins over whatever the control plane says,
	// because on a cluster node the installer's list IS the trust decision.
	if got := Place(team, TeamAsyncScanOff, true); got != PlacementRemote {
		t.Errorf("cluster node with a rendered node list placed %q, want %q", got, PlacementRemote)
	}
	// The org turned it off and there is no rendered list → skip, honestly.
	if got := Place(team, TeamAsyncScanOff, false); got != PlacementSkip {
		t.Errorf("team_async_scan=off placed %q, want %q", got, PlacementSkip)
	}
	// An unknown value from a newer master must fail CLOSED (skip), never remote:
	// sending content somewhere on the strength of a value we do not understand is
	// the one outcome that cannot be undone.
	if got := Place(team, TeamAsyncScan("some_future_mode"), false); got != PlacementSkip {
		t.Errorf("unknown team_async_scan placed %q, want %q (fail closed)", got, PlacementSkip)
	}
}

// TestAsyncRules_SingleChunkPieceNoRuleJob: a piece the synchronous layer already
// covered end to end produces no asynchronous rule work at all.
//
// Every piece at or under the 16 KiB sync cap is in this category — which is
// almost all of them. Enqueueing them would spend a node round-trip and a
// detector invocation per piece to produce findings that head-dedup then throws
// away. spec: R-scan-node-deepscan-16.S3
func TestAsyncRules_SingleChunkPieceNoRuleJob(t *testing.T) {
	for _, size := range []int{1, 512, 8 * 1024, scanchunk.SizeBytes} {
		text := strings.Repeat("a", size)
		chunks := scanchunk.Chunks(text, len(text), scanchunk.SizeBytes, scanchunk.OverlapDefault)
		if len(chunks) != 0 {
			t.Errorf("a %d-byte piece fully covered by the fast layer produced %d rule chunks", size, len(chunks))
		}
		if NeedsRuleJob(CommittedPiece{Text: text, HeadBytes: len(text)}) {
			t.Errorf("a %d-byte fully-scanned piece was marked as needing a rule job", size)
		}
	}
	// ...and a piece with an unscanned tail DOES need one, or the lane never runs.
	long := strings.Repeat("a", 40*1024)
	if !NeedsRuleJob(CommittedPiece{Text: long, HeadBytes: scanchunk.SizeBytes}) {
		t.Error("a 40 KiB piece with a 16 KiB head needs a rule job; without it the tail is never scanned")
	}
	// A degraded fast layer inspected nothing, so even a short piece needs one.
	if !NeedsRuleJob(CommittedPiece{Text: strings.Repeat("a", 100), HeadBytes: 0}) {
		t.Error("head_bytes=0 means the fast layer was degraded and saw nothing; the async lane must cover it")
	}
}

// TestAsyncScanPlacement_UnixSinkV2IsLocalOnly pins the local transport: it
// carries no token, because there is nothing to authorize against on the same
// machine — and a token on this path would be one more place a credential lives.
func TestAsyncScanPlacement_UnixSinkV2IsLocalOnly(t *testing.T) {
	f := deepscan.FrameV2{
		Version: int(deepscan.FrameVersionV2), JobID: "j", TenantID: "org_a",
		Source: deepscan.SourceRequest, Prompt: "x",
	}
	b, err := deepscan.EncodeFrameV2(f)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if strings.Contains(string(b), "sct1") || strings.Contains(string(b), `"token"`) {
		t.Errorf("the local frame carries a token: %s", b)
	}
}
