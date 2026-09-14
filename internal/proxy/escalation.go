// escalation.go — request-level escalation primitives.
//
// The compliance detector decides per CONTENT PIECE. An escalation rule
// ("≥L4 hits ≥3 → block") is a statement about the REQUEST as a whole, so
// somebody has to turn N per-piece finding lists into one number. That is all
// this file does today; the rule evaluation and the dispatcher wiring land on
// top of it.
//
// spec: R-compliance-grading-16 (计数按值去重，代理本地临时算，不进 wire 不落库)
package proxy

// Finding is the proxy-side decoded view of one detector finding, holding only
// the fields the request-level counter reads. The detector ships findings as
// raw JSON over the pipe (pipewire.Response.Findings) and the dispatcher
// forwards them to master as map[string]any, so this type is a LOCAL READ VIEW
// — decoding into it neither reshapes nor filters what is uploaded.
//
// Field names and JSON tags are taken verbatim from the compliance intake wire
// (方案 §4b.1). Decoding a wire that carries more fields than this is fine and
// expected: encoding/json ignores the rest, and none of them are re-encoded
// from here.
//
// 🔴 NOTHING CONTENT-DERIVED MAY BE ADDED HERE. No hash, no fingerprint, no
// digest, no matched substring. The counter slices the value out of the piece
// text it already holds and drops it; putting a comparable digest on a Finding
// would create an "hash a known ID card, look up who mentioned that person"
// search surface over the audit store. That is a privacy property change, not
// an implementation detail (R-compliance-grading-16, and its .S3 regression
// scenario checks all four surfaces stay clean).
type Finding struct {
	// StartOffset / EndOffset are a [start, end) byte span. 🔴 PER-PIECE ONLY:
	// they index the head THIS piece sent to the detector, which is a prefix of
	// pieces[i].text (filter_dispatch.go caps the payload at pipeInputCap on a
	// rune boundary and re-attaches the tail after masking). Piece #2's [10,21)
	// is a completely different substring from piece #1's [10,21) — see
	// injectWireLabels for the same warning on the labelling join.
	StartOffset int `json:"start_offset"`
	EndOffset   int `json:"end_offset"`
	// Level is the classification level (1..N) resolved from the tenant's
	// classification tree. It is `omitempty` on the wire, so a detector that
	// predates grading — or a finding no leaf claims — decodes to 0, meaning
	// UNGRADED. 0 satisfies no level floor of 1 or higher, which is the
	// intended direction: an ungraded hit never helps reach a stronger action.
	Level int `json:"level"`
	// Confirmed is the EVIDENCE GATE'S VERDICT (allow-list, value checksum,
	// entropy, positive/negative context together), not a score.
	//
	// 🔴 It is deliberately NOT Confidence. A high-scoring hit whose context the
	// gate rejected must not be counted toward escalation — otherwise a scored
	// maybe can help assemble a block. This distinction is the whole reason
	// R-compliance-grading-16 exists as its own rule.
	Confirmed bool `json:"confirmed"`
}

// countDistinctHits counts how many DISTINCT confirmed values at or above
// minLevel the request contains — the input to every escalation rule's
// min_count. findings[i] belongs to pieces[i].
//
// skipped is how many hits PASSED the confirmed/level filters but could not be
// resolved to a value (see the fail-open paragraph below). It is returned rather
// than logged here on purpose: this is a pure function with no request context,
// and the logging convention requires every WARN to carry request_id/trace_id —
// a WARN raised from here would be an orphan nobody can attribute. 🔴 THE CALLER
// (which has the request context) MUST SURFACE A NON-ZERO skipped: a hit the
// counter could not verify means the detector's offsets and the proxy's text
// disagree, which is exactly the kind of cross-process desync that must not pass
// quietly. Being a number rather than a log line, it can also be counted onto
// the health surface later.
//
// spec: R-compliance-grading-16.S1 (同一实体值重复出现不重复计数)
// spec: R-compliance-grading-16.S2 (跨片段去重先切字符串再比，不比偏移)
//
// WHY dedup by VALUE, and why the value has to be re-sliced here:
//   - Counting by entity_type makes three different ID cards score 1.
//   - Counting raw hits (or pieces) makes the same ID card quoted three times
//     score 3.
//     Both are exactly what a cumulative-escalation rule must not do, so the unit
//     is the distinct matched value.
//   - The value is not on the wire and must never be: the proxy already holds
//     both the text and the offsets, and the detector has already remapped those
//     offsets back onto the frame the proxy sent (filter_dispatch.go's
//     injectWireLabels documents the same equal-join). So this is a lookup of an
//     answer already computed, done in memory and thrown away — no new field, no
//     upload, no row.
//
// 🔴 OFFSETS ARE NEVER THE IDENTITY. Two hits with the same [start, end) in
// different pieces are two different strings; two hits with different spans in
// different pieces may be the same string. The span is only ever used to slice
// its OWN piece, and the resulting substrings are what get compared.
//
// Hits that cannot be sliced (span outside the piece text, inverted, zero-width,
// or a findings row with no piece) are counted into skipped rather than into the
// result as one anonymous unit each: their value is unknown, so they can neither
// be deduped against a known value nor honestly claimed as distinct — and this
// counter only ever pushes a request toward a STRONGER action, so an unverifiable
// hit must not be allowed to help reach a block. This matches the sync detection
// lane's fail-open budget rule. skipped is what keeps that fail-open from being
// silent.
//
// Note skipped counts HITS, not distinct values: with no value there is nothing
// to dedupe on, so two skipped hits may or may not have been the same string.
// Hits the rules exclude (unconfirmed, below the level floor) are not skips —
// they are working as intended and must not raise a WARN at the caller.
func countDistinctHits(pieces []contentPiece, findings [][]Finding, minLevel int) (count int, skipped int) {
	distinct := make(map[string]struct{})
	for i := range findings {
		// A findings row past the end of pieces has no text to slice against.
		// Its hits still get tallied as skips (rather than the loop breaking out)
		// because that mismatch is itself the desync worth reporting.
		var text string
		havePiece := i < len(pieces)
		if havePiece {
			text = pieces[i].text
		}
		for _, f := range findings[i] {
			if !f.Confirmed || f.Level < minLevel {
				continue
			}
			if !havePiece {
				skipped++
				continue
			}
			value, ok := hitValue(text, f)
			if !ok {
				skipped++
				continue
			}
			distinct[value] = struct{}{}
		}
	}
	return len(distinct), skipped
}

// hitValue slices one finding's matched text out of the piece it was found in.
// ok=false when the span does not address a non-empty region of this piece's
// text — the caller skips the hit (see countDistinctHits for why skipping is the
// safe direction).
func hitValue(text string, f Finding) (string, bool) {
	if f.StartOffset < 0 || f.EndOffset <= f.StartOffset || f.EndOffset > len(text) {
		return "", false
	}
	return text[f.StartOffset:f.EndOffset], true
}
