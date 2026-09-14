package proxy

import (
	"strings"
	"testing"
)

// Fences for R-compliance-grading-16.S1 / .S2 — the escalation counting unit.
//
// Both tests are written against countDistinctHits ONLY (a pure function). They
// deliberately do not go through the dispatcher: the thing under test is "what
// counts as one hit", and mixing in the request path would let a green here
// mean "the pipeline happened to agree", not "the counting rule holds".

// hitAt builds a finding for the FIRST occurrence of value inside text.
//
// The offsets are computed here rather than hand-counted so that a test reading
// as "this piece contains this ID card number" cannot silently drift into
// asserting the wrong span. countDistinctHits does no searching of its own — it
// only slices what these offsets point at.
func hitAt(t *testing.T, text, value string, level int, confirmed bool) Finding {
	t.Helper()
	i := strings.Index(text, value)
	if i < 0 {
		t.Fatalf("test fixture is wrong: %q does not contain %q", text, value)
	}
	return Finding{
		StartOffset: i,
		EndOffset:   i + len(value),
		Level:       level,
		Confirmed:   confirmed,
	}
}

// TestEscalation_DedupesByValueNotType guards R-compliance-grading-16.S1:
// the counting unit is the matched VALUE, not the entity type and not the piece.
//
// Same ID card in three pieces → 1 (no escalation under "≥L4, ≥3 hits").
// Three different ID cards      → 3 (escalation fires).
//
// A count-by-entity-type implementation returns 1 for BOTH halves; a
// count-by-hit / count-by-piece implementation returns 3 for both. Only
// per-value dedup satisfies the pair.
func TestEscalation_DedupesByValueNotType(t *testing.T) {
	const (
		idA = "110101199003071234"
		idB = "310101198807153695"
		idC = "440305197502289517"
	)

	t.Run("same value in three pieces counts once", func(t *testing.T) {
		pieces := []contentPiece{
			{text: "please verify customer " + idA + " for me"},
			{text: "reminder: " + idA + " is the account holder"},
			{text: idA + " appears again at offset zero here"},
		}
		findings := [][]Finding{
			{hitAt(t, pieces[0].text, idA, 4, true)},
			{hitAt(t, pieces[1].text, idA, 4, true)},
			{hitAt(t, pieces[2].text, idA, 4, true)},
		}

		got, skipped := countDistinctHits(pieces, findings, 4)
		if got != 1 {
			t.Fatalf("same ID card in three pieces: count = %d, want 1 (would escalate at 3)", got)
		}
		if skipped != 0 {
			t.Fatalf("every hit is sliceable: skipped = %d, want 0", skipped)
		}
	})

	t.Run("three different values count three", func(t *testing.T) {
		pieces := []contentPiece{
			{text: "please verify customer " + idA + " for me"},
			{text: "reminder: " + idB + " is the account holder"},
			{text: idC + " appears again at offset zero here"},
		}
		findings := [][]Finding{
			{hitAt(t, pieces[0].text, idA, 4, true)},
			{hitAt(t, pieces[1].text, idB, 4, true)},
			{hitAt(t, pieces[2].text, idC, 4, true)},
		}

		got, skipped := countDistinctHits(pieces, findings, 4)
		if got != 3 {
			t.Fatalf("three different ID cards: count = %d, want 3 (escalation must fire)", got)
		}
		if skipped != 0 {
			t.Fatalf("every hit is sliceable: skipped = %d, want 0", skipped)
		}
	})

	t.Run("repeats inside one piece also collapse", func(t *testing.T) {
		text := idA + " and again " + idA + " plus " + idB
		pieces := []contentPiece{{text: text}}
		second := strings.LastIndex(text, idA)
		findings := [][]Finding{{
			hitAt(t, text, idA, 4, true),
			{StartOffset: second, EndOffset: second + len(idA), Level: 4, Confirmed: true},
			hitAt(t, text, idB, 4, true),
		}}

		got, skipped := countDistinctHits(pieces, findings, 4)
		if got != 2 {
			t.Fatalf("two distinct values, one repeated within a piece: count = %d, want 2", got)
		}
		if skipped != 0 {
			t.Fatalf("every hit is sliceable: skipped = %d, want 0", skipped)
		}
	})
}

// TestEscalation_SameOffsetDifferentPieceCountsTwice guards
// R-compliance-grading-16.S2: offsets are PER-PIECE, so an equal offset pair
// across two pieces says nothing about the values being equal.
//
// This is the fence for the specific wrong implementation that is cheap to
// write and passes the S1 test: dedup on the [start,end) pair. That
// implementation returns 1 here; slicing each piece's own text first returns 2.
func TestEscalation_SameOffsetDifferentPieceCountsTwice(t *testing.T) {
	// Both prefixes are exactly 10 bytes and both values exactly 11 bytes, so
	// both hits land on the identical span [10,21) — the whole point.
	pieces := []contentPiece{
		{text: "acct A -> 13800138000"},
		{text: "acct B -> 13900139000"},
	}
	findings := [][]Finding{
		{{StartOffset: 10, EndOffset: 21, Level: 4, Confirmed: true}},
		{{StartOffset: 10, EndOffset: 21, Level: 4, Confirmed: true}},
	}

	// Guard the fixture itself: if either span stops being [10,21) this test
	// silently stops testing what it claims to.
	if got := pieces[0].text[10:21]; got != "13800138000" {
		t.Fatalf("fixture drift: piece 0 span [10,21) = %q", got)
	}
	if got := pieces[1].text[10:21]; got != "13900139000" {
		t.Fatalf("fixture drift: piece 1 span [10,21) = %q", got)
	}

	got, skipped := countDistinctHits(pieces, findings, 4)
	if got != 2 {
		t.Fatalf("identical spans over different piece text: count = %d, want 2 "+
			"(offsets are per-piece; equal offsets are NOT equal values)", got)
	}
	if skipped != 0 {
		t.Fatalf("both hits are sliceable: skipped = %d, want 0", skipped)
	}
}

// TestCountDistinctHits_DegenerateInputsCountZero covers the boundaries of the
// primitive itself: nothing to count, nothing confirmed, nothing at or above the
// level floor, and findings that cannot be sliced. None of them may panic, and
// none of them may invent a countable unit — the counter drives escalation to a
// STRONGER action, so an unverifiable hit must not push a request toward block.
func TestCountDistinctHits_DegenerateInputsCountZero(t *testing.T) {
	text := "customer 110101199003071234 filed a claim"
	confirmedL4 := hitAt(t, text, "110101199003071234", 4, true)

	cases := []struct {
		name     string
		pieces   []contentPiece
		findings [][]Finding
		minLevel int
		// wantSkipped separates "the rules excluded this hit" (0 — working as
		// intended) from "this hit could not be resolved to a value" (1 — the
		// caller must WARN). Both produce count 0, which is exactly why the two
		// have to be told apart here.
		wantSkipped int
	}{
		{name: "no pieces and no findings", minLevel: 4},
		{name: "pieces but no findings", pieces: []contentPiece{{text: text}}, minLevel: 4},
		{
			name:     "findings rows all empty",
			pieces:   []contentPiece{{text: text}},
			findings: [][]Finding{{}},
			minLevel: 4,
		},
		{
			name:     "hit not confirmed by the evidence gate",
			pieces:   []contentPiece{{text: text}},
			findings: [][]Finding{{hitAt(t, text, "110101199003071234", 4, false)}},
			minLevel: 4,
		},
		{
			name:     "hit below the level floor",
			pieces:   []contentPiece{{text: text}},
			findings: [][]Finding{{hitAt(t, text, "110101199003071234", 2, true)}},
			minLevel: 4,
		},
		{
			name:     "ungraded hit (no level on the wire) against a level floor",
			pieces:   []contentPiece{{text: text}},
			findings: [][]Finding{{hitAt(t, text, "110101199003071234", 0, true)}},
			minLevel: 1,
		},
		{
			name:        "more findings rows than pieces",
			pieces:      nil,
			findings:    [][]Finding{{confirmedL4}},
			minLevel:    4,
			wantSkipped: 1,
		},
		{
			name:        "end offset past the piece text",
			pieces:      []contentPiece{{text: text}},
			findings:    [][]Finding{{{StartOffset: 0, EndOffset: len(text) + 5, Level: 4, Confirmed: true}}},
			minLevel:    4,
			wantSkipped: 1,
		},
		{
			name:        "negative start offset",
			pieces:      []contentPiece{{text: text}},
			findings:    [][]Finding{{{StartOffset: -1, EndOffset: 4, Level: 4, Confirmed: true}}},
			minLevel:    4,
			wantSkipped: 1,
		},
		{
			name:        "inverted span",
			pieces:      []contentPiece{{text: text}},
			findings:    [][]Finding{{{StartOffset: 12, EndOffset: 4, Level: 4, Confirmed: true}}},
			minLevel:    4,
			wantSkipped: 1,
		},
		{
			name:        "zero-width span",
			pieces:      []contentPiece{{text: text}},
			findings:    [][]Finding{{{StartOffset: 9, EndOffset: 9, Level: 4, Confirmed: true}}},
			minLevel:    4,
			wantSkipped: 1,
		},
		{
			name:        "empty piece text with a stale span",
			pieces:      []contentPiece{{text: ""}},
			findings:    [][]Finding{{{StartOffset: 0, EndOffset: 3, Level: 4, Confirmed: true}}},
			minLevel:    4,
			wantSkipped: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, skipped := countDistinctHits(tc.pieces, tc.findings, tc.minLevel)
			if got != 0 {
				t.Fatalf("count = %d, want 0", got)
			}
			if skipped != tc.wantSkipped {
				t.Fatalf("skipped = %d, want %d", skipped, tc.wantSkipped)
			}
		})
	}
}

// TestCountDistinctHits_MinLevelZeroCountsUngradedHits pins the other side of
// the level floor: with no floor configured (minLevel 0) an ungraded hit — an
// older detector that does not emit `level` — still counts. Excluding it there
// would make "no floor" quietly mean "graded hits only".
func TestCountDistinctHits_MinLevelZeroCountsUngradedHits(t *testing.T) {
	text := "customer 110101199003071234 filed a claim"
	pieces := []contentPiece{{text: text}}
	findings := [][]Finding{{hitAt(t, text, "110101199003071234", 0, true)}}

	got, skipped := countDistinctHits(pieces, findings, 0)
	if got != 1 {
		t.Fatalf("ungraded confirmed hit with no level floor: count = %d, want 1", got)
	}
	if skipped != 0 {
		t.Fatalf("the hit is sliceable: skipped = %d, want 0", skipped)
	}
}

// TestCountDistinctHits_SkippedReportsUnresolvableHits is the fence for the
// second return value: a hit that passes the confirmed/level filters but cannot
// be resolved to a value must be REPORTED, not dropped in silence.
//
// WHY this needs its own fence rather than riding on the count: an unresolvable
// hit and an excluded hit both leave the count unchanged, so the count alone can
// never tell "nothing qualified" apart from "the detector's offsets and the
// proxy's text disagree". Only the second is a defect, and only the caller —
// which holds the request context the logging convention requires — can WARN
// about it. If this number stops being produced, that desync goes quiet again.
func TestCountDistinctHits_SkippedReportsUnresolvableHits(t *testing.T) {
	const (
		idA = "110101199003071234"
		idB = "310101198807153695"
	)
	pieces := []contentPiece{
		{text: "customer " + idA + " called"},
		{text: "customer " + idB + " called"},
	}
	findings := [][]Finding{
		{
			hitAt(t, pieces[0].text, idA, 4, true),                      // counts
			{StartOffset: 3, EndOffset: 900, Level: 4, Confirmed: true}, // past the text → skip
			{StartOffset: 40, EndOffset: 12, Level: 4, Confirmed: true}, // inverted     → skip
			hitAt(t, pieces[0].text, idA, 4, false),                     // unconfirmed  → excluded, NOT a skip
			{StartOffset: 0, EndOffset: 8, Level: 1, Confirmed: true},   // below floor  → excluded, NOT a skip
		},
		{
			hitAt(t, pieces[1].text, idB, 4, true), // counts
		},
		// A third findings row with no matching piece: the detector and the proxy
		// disagree about how many pieces were scanned. Its qualifying hit is a
		// skip, and staying silent about it is the failure this return value exists
		// to prevent.
		{
			{StartOffset: 0, EndOffset: 5, Level: 4, Confirmed: true},  // skip
			{StartOffset: 0, EndOffset: 5, Level: 4, Confirmed: false}, // excluded, NOT a skip
		},
	}

	count, skipped := countDistinctHits(pieces, findings, 4)
	if count != 2 {
		t.Fatalf("count = %d, want 2 (the two sliceable, distinct, confirmed L4 hits)", count)
	}
	if skipped != 3 {
		t.Fatalf("skipped = %d, want 3 (out-of-range + inverted + the row with no piece); "+
			"excluded-by-rule hits must NOT be reported as skips", skipped)
	}
}
