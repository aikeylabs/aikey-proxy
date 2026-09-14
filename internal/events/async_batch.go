package events

import "context"

// UploadAsyncComplianceBatch uploads asynchronous-scan events as their OWN batch.
//
// 🔴 SEPARATE BATCH, NOT AN OPTIMISATION — A BLAST-RADIUS DECISION.
// Asynchronous events carry a field (scan_coverage) that a master older than
// 2026-09 does not know, and the publish order is master first, then proxies
// (design §4b.12), so there is a window where a new proxy talks to an old master.
// An intake batch fails or succeeds as a whole. If the async events rode along
// with the fast layer's events and the old master rejected the batch, a NEW proxy
// would take the SYNCHRONOUS audit trail down with it — a compliance outage
// caused by an optional observability field on a best-effort lane.
//
// Batching them apart means the worst case is "the async events are dead-lettered
// and retried", which is exactly what that lane is allowed to do.
//
// The events must already be encoded for the target master (asyncscan.EncodeForMaster
// strips what the master has not advertised).
//
// spec: R-scan-node-deepscan-19.S2 · fence: TestUploadAsyncComplianceBatch_NeverMixesWithFastLayer
func (r *Reporter) UploadAsyncComplianceBatch(ctx context.Context, routeSource string, eventJSONs [][]byte) error {
	if len(eventJSONs) == 0 {
		return nil
	}
	// Deliberately the SAME transport and dead-letter path as the fast layer —
	// only the batch boundary differs. A second upload path would be a second
	// thing to keep in step with retries, dead-letter format and route resolution.
	return r.UploadComplianceEvents(ctx, routeSource, eventJSONs)
}
