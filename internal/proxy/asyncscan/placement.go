package asyncscan

import "github.com/AiKeyLabs/pkg/scanchunk"

// TeamAsyncScan is the organisation's answer to "where may team content be
// scanned asynchronously?", delivered by the control plane (design §4b.8).
type TeamAsyncScan string

const (
	// TeamAsyncScanNodes: the org advertises scan nodes; team content may go to them.
	TeamAsyncScanNodes TeamAsyncScan = "nodes"
	// TeamAsyncScanLocal: scan on the member's own machine (Trial, or Production
	// with no nodes deployed).
	TeamAsyncScanLocal TeamAsyncScan = "local"
	// TeamAsyncScanOff: no asynchronous scanning of team content.
	TeamAsyncScanOff TeamAsyncScan = "off"
)

// Placement is where one piece will be scanned.
type Placement string

const (
	PlacementRemote Placement = "remote"
	PlacementLocal  Placement = "local"
	PlacementSkip   Placement = "skip"
)

// Place decides where one committed piece is scanned.
//
// 🔴 RULE ONE, NO EXCEPTIONS: a personal-routed piece is scanned locally or not
// at all. It is an individual's own content, on their own machine, for their own
// self-view — there is no organization behind it, no tenant a node could
// authorize it against, and nobody who agreed to it being sent anywhere. Every
// other input to this function is irrelevant once Personal is true, and the fence
// TestAsyncScanPlacement_PersonalPieceNeverLeavesMachine checks that exhaustively
// because the plausible regression is a later "...unless the org forces it"
// branch that only fires in one combination. spec: R-scan-node-deepscan-16.S1
//
// 🔴 RULE TWO: an unrecognized policy value FAILS CLOSED. A newer master could
// send a mode this binary has never heard of; treating it as "remote" would ship
// raw content somewhere on the strength of a string we cannot interpret, and that
// is the one decision here that cannot be taken back. Skipping loses coverage,
// which is visible in the health counters and recoverable by upgrading.
//
// clusterNodes is the installer-rendered node list on a cluster node. It wins over
// the control plane's answer because on a cluster node that rendered list IS the
// trust decision (design §4b.8: Cluster reads cluster-node.env, not the API).
func Place(p CommittedPiece, ts TeamAsyncScan, clusterNodes bool) Placement {
	if p.Personal {
		return PlacementLocal
	}
	if clusterNodes {
		return PlacementRemote
	}
	switch ts {
	case TeamAsyncScanNodes:
		return PlacementRemote
	case TeamAsyncScanLocal:
		return PlacementLocal
	case TeamAsyncScanOff:
		return PlacementSkip
	default:
		// Includes "" (no policy fetched yet) and anything a newer master invents.
		return PlacementSkip
	}
}

// NeedsRuleJob reports whether this piece has any bytes the synchronous layer did
// not inspect.
//
// Almost every piece is at or under the 16 KiB sync cap, so almost every piece
// answers false — and that is the point. Enqueueing a fully-scanned piece costs a
// node round-trip and a detector invocation to produce findings that head-dedup
// (design §3.6: drop findings ending at or before head_bytes) then discards.
// spec: R-scan-node-deepscan-16.S3
//
// head_bytes == 0 means the fast layer DEGRADED and inspected nothing, so even a
// short piece needs the async lane — that is the case where the synchronous
// guarantee already failed and this lane is the only remaining coverage.
func NeedsRuleJob(p CommittedPiece) bool {
	if p.Text == "" {
		return false
	}
	return len(scanchunk.Chunks(p.Text, p.HeadBytes, scanchunk.SizeBytes, scanchunk.OverlapDefault)) > 0 &&
		p.HeadBytes < len(p.Text)
}
