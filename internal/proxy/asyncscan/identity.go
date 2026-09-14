// Package asyncscan is the proxy's INBOUND half of the asynchronous scan lane:
// deciding what to enqueue, remembering what has already been scanned, merging
// results, and building the audit events.
//
// The outbound half (frame assembly, delivery, failover) lives in
// internal/proxy/deepscanfwd. The split follows the security boundary, not the
// call graph: that package decides what leaves the machine, this one decides
// what the organization is told.
//
// spec: R-scan-node-deepscan-4.S1 / -15.S1 / -15.S2 / -23.S1 · design §3.3, §3.7, §4b.2
package asyncscan

import (
	"crypto/sha256"
	"encoding/hex"
)

// PieceID is the content-derived identity of one piece.
type PieceID struct {
	// ContentSHA256 is the hash of the WHOLE piece, not just the scanned head.
	ContentSHA256 string
	// AuditUnitID is the audit row this piece owns, derived from (scope, content).
	AuditUnitID string
}

// PieceIdentity derives the piece's content hash and audit unit.
//
// 🔴 IT HASHES THE WHOLE PIECE, and that is the difference from the fast layer.
// The fast layer hashes only the head it actually scanned (filter_cache.go
// hashHead) — correct for its own cache, because the head is all it ever looked
// at. The async lane looks at everything, so reusing the head hash would mean a
// user could get one long document scanned and then append arbitrary content to
// it forever: every later version shares the head, so every later version would
// be recognized as "already scanned" and skipped.
//
// Fence: TestAsyncScanIdentity_SameHeadDifferentTailTwoUnits.
func PieceIdentity(scopeKey, text string) PieceID {
	sum := sha256.Sum256([]byte(text))
	content := hex.EncodeToString(sum[:])
	return PieceID{ContentSHA256: content, AuditUnitID: auditUnitID(scopeKey, content)}
}

// auditUnitID mirrors internal/proxy.auditUnitID byte for byte.
//
// 🔴 The duplication is deliberate and must stay exact. The fast layer and this
// lane have to land on the SAME row for the same content in the same scope — that
// is what makes a re-scan idempotent at ingest. The function is three lines and
// unexported on both sides; exporting one for the other would widen the proxy's
// internal API for no gain, and a shared helper package for a sha256 call would
// be the kind of premature abstraction this project has been burned by. What
// keeps them honest is that both are pinned by fences that use literal expected
// ids.
func auditUnitID(scopeKey, contentHash string) string {
	sum := sha256.Sum256([]byte("aikey-audit-unit\x00" + scopeKey + "\x00" + contentHash))
	return "au_" + hex.EncodeToString(sum[:16])
}

// DeepScanEventID / RuleScanEventID derive the async events' ids from the audit
// unit (design §4b.6).
//
// 🔴 DERIVED, NEVER RANDOM. The async lane re-scans by construction: the
// already-scanned record lives in memory and a proxy restart clears it. With
// random ids, every restart would re-file the same violations as new audit rows —
// which is precisely the flood fixed on 2026-09-08 when the fast layer's ids
// stopped coming from the detector's CSPRNG
// (bugfix 2026-09-08-compliance-audit-unit-id-parasitic-on-cache.md). Two ingest
// paths' ON CONFLICT (event_id) can absorb a replay; they cannot absorb a re-scan.
//
// The two engines get different ids because they are two different findings about
// the same content and a reviewer needs both rows.
func DeepScanEventID(auditUnitID string) string {
	return derivedEventID("ad_", "async_deep", auditUnitID)
}

// RuleScanEventID is the rule back-scan's event id.
func RuleScanEventID(auditUnitID string) string {
	return derivedEventID("ar_", "async_rule", auditUnitID)
}

func derivedEventID(prefix, domain, auditUnitID string) string {
	sum := sha256.Sum256([]byte(domain + "\x00" + auditUnitID))
	return prefix + hex.EncodeToString(sum[:16])
}

// PieceIdentityForContent derives the audit unit from an ALREADY-HASHED content
// digest, for callers that computed the hash elsewhere (and for the parity fence
// in internal/proxy, which must compare the two auditUnitID implementations on
// the same inputs).
func PieceIdentityForContent(scopeKey, contentSHA256 string) PieceID {
	return PieceID{ContentSHA256: contentSHA256, AuditUnitID: auditUnitID(scopeKey, contentSHA256)}
}
