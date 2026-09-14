package asyncscan

import (
	"encoding/json"

	"github.com/AiKeyLabs/pkg/deepscan"
)

// FeatureScanCoverage is the capability string master advertises in
// GET /v1/compliance/policy → intake_features when it can store scan_coverage
// (design §4b.12).
const FeatureScanCoverage = "scan_coverage"

// Finalize decides whether this result ENDS the piece's scanning, and returns
// the coverage to record.
//
// 🔴 The axis is final vs not-final, NOT complete vs partial, and conflating them
// is the bug this function exists to prevent:
//
//   - piece_cap partial is FINAL. The cap is deterministic, so re-sending the
//     same piece produces the same truncation. Treating it as unfinished
//     re-enqueues every oversized piece on every turn of the conversation.
//   - transient partial is NOT final. Nothing was scanned; the content deserves
//     another try when it reappears — but only up to maxTransientAttempts, or a
//     permanently unreachable node turns every turn into a re-enqueue of the
//     whole history.
//
// attempts is how many transient failures this piece has already had.
func Finalize(m MergedResult, attempts int) (bool, *Coverage) {
	cov := m.Coverage
	if cov.Status == "" {
		cov.Status = deepscan.StatusComplete
	}

	if cov.Status == deepscan.StatusPartial && cov.Reason == deepscan.ReasonTransient {
		if attempts < maxTransientAttempts {
			return false, nil
		}
		// Out of attempts: record honestly that we gave up, rather than letting
		// the piece disappear with no row at all.
		cov.Reason = deepscan.ReasonTransient
		return true, &cov
	}
	return true, &cov
}

// EncodeForMaster serializes events for upload, removing fields the target
// master has not advertised support for.
//
// 🔴 WHY STRIP RATHER THAN NOT-BUILD. The events are built once, and the same
// built event may be uploaded now (to a master whose capabilities are known) or
// replayed later from the dead letter (to a master that may have been upgraded,
// or not). Deciding at ENCODE time means the dead-letter replay asks the question
// again against whatever master is there then — whereas deciding at build time
// would freeze a stale answer into the stored bytes.
//
// features is the intake_features list from the org policy; an empty or nil list
// is an old master and gets the conservative encoding.
func EncodeForMaster(events []Event, features []string) [][]byte {
	supportsCoverage := false
	for _, f := range features {
		if f == FeatureScanCoverage {
			supportsCoverage = true
			break
		}
	}
	out := make([][]byte, 0, len(events))
	for i := range events {
		ev := events[i] // a COPY on purpose — see the strip below
		if !supportsCoverage {
			// Strip by clearing the pointer on a COPY: ev is a value, so this does
			// not mutate the caller's slice — a dead-letter replay against a newer
			// master must still be able to send the field.
			ev.ScanCoverage = nil
		}
		b, err := json.Marshal(ev)
		if err != nil {
			// A finding that cannot be marshaled is a programming error, not a
			// runtime condition. Dropping the event silently would be the worst
			// outcome, so skip this one and keep the rest of the batch.
			continue
		}
		out = append(out, b)
	}
	return out
}
