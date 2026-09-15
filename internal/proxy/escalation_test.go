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

// ─────────────────────────────────────────────────────────────────────────────
// Family filter: `category="secret"` never participates in the cumulative count
// (R-compliance-grading-17.S1 / .S2, DEC-compliance-grading-11 决定 3).
//
// 🔴 WHAT IS AND IS NOT BEING ASSERTED HERE. The rule excludes credential hits
// from ONE thing: the request-level cumulative count. It does NOT stop them
// being detected, does NOT stop them producing an audit event, and does NOT
// change what may be done to the tool block they were found in (that ceiling is
// blockScanPolicy's, and TestBlockScanPolicy_* is what guards it). "secret 不
// 计入累计" and "secret 不管了" are different sentences; only the first one is
// the rule.
//
// WHY the rule exists at all: the built-in credential ruleset is the 224-rule
// gitleaks derivation in ai-compliance-detector/internal/baselines/built-in/
// credentials.yaml, and tool blocks were opened for scanning in 2026-08-10
// precisely on the promise that those rules "永不在 agent 读文件时触发". An agent
// handing back a config file with three API keys through `tool_result` is a
// normal working turn, not somebody exfiltrating customer records. Letting those
// three hits assemble a block would dismantle that promise from the side —
// through the cumulative path instead of through the ceiling.
// ─────────────────────────────────────────────────────────────────────────────

const (
	// escalationMinLevel / escalationMinCount are the two halves of the rule
	// these fences are written against: "≥L4 命中 ≥3 条 → 拦截".
	//
	// They are TEST-LOCAL on purpose. The evaluator that reads a tenant's real
	// min_count lands in a later step; naming the numbers here is what lets each
	// assertion below say "this WOULD have escalated" / "this would NOT" rather
	// than compare against a bare literal whose meaning the next reader has to
	// reconstruct.
	escalationMinLevel = 4
	escalationMinCount = 3
)

// Synthetic credentials. Not real keys, and deliberately not real-looking
// enough to be mistaken for one — the counter never inspects what the value
// means, only whether two values are the same string.
const (
	apiKeyA = "sk-fixture-aaaa0000000000000000000001"
	apiKeyB = "sk-fixture-bbbb0000000000000000000002"
	apiKeyC = "sk-fixture-cccc0000000000000000000003"
)

// toolResultPiece runs a REAL `tool_result` body through the REAL extractor
// instead of hand-writing a contentPiece literal.
//
// WHY through the extractor: a literal would let the fixture claim "this is what
// an agent tool block looks like" while quietly differing from one — in
// particular in `ceiling`, which is the field these tests assert did NOT move.
// Reading it out of extractFilterableContent means the audit-only ceiling in the
// assertions is the one blockScanPolicy actually produces today.
func toolResultPiece(t *testing.T, payload string) []contentPiece {
	t.Helper()
	body := `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":` +
		mustJSON(t, payload) + `}]}]}`
	pieces, _, ok := extractFilterableContent([]byte(body))
	if !ok || len(pieces) != 1 {
		t.Fatalf("fixture is wrong: a tool_result body must yield exactly one scannable piece; ok=%v pieces=%d", ok, len(pieces))
	}
	if pieces[0].text != payload {
		t.Fatalf("fixture is wrong: extracted text %q != payload %q", pieces[0].text, payload)
	}
	if pieces[0].ceiling != ceilingAudit {
		t.Fatalf("premise broken: tool blocks must arrive audit-capped, got %v — "+
			"if this moved, TestBlockScanPolicy_ToolBlocksAreAuditOnly is the fence to read first", pieces[0].ceiling)
	}
	return pieces
}

// categorizedHit is hitAt plus the family label. It reuses hitAt so the offset
// arithmetic stays in exactly one place.
func categorizedHit(t *testing.T, text, value, category string, level int) Finding {
	t.Helper()
	f := hitAt(t, text, value, level, true)
	f.Category = category
	return f
}

// TestEscalation_SecretCategoryExcludedFromCount guards
// R-compliance-grading-17.S1: an agent returning a config file with three
// different API keys through `tool_result` must not be blocked by the cumulative
// rule.
func TestEscalation_SecretCategoryExcludedFromCount(t *testing.T) {
	configFile := "AWS_ACCESS_KEY=" + apiKeyA + "\nSTRIPE_KEY=" + apiKeyB + "\nOPENAI_KEY=" + apiKeyC + "\n"

	t.Run("three distinct API keys count zero and the request is not escalated", func(t *testing.T) {
		pieces := toolResultPiece(t, configFile)
		findings := [][]Finding{{
			categorizedHit(t, configFile, apiKeyA, "secret", escalationMinLevel),
			categorizedHit(t, configFile, apiKeyB, "secret", escalationMinLevel),
			categorizedHit(t, configFile, apiKeyC, "secret", escalationMinLevel),
		}}

		count, skipped := countDistinctHits(pieces, findings, escalationMinLevel)
		if count != 0 {
			t.Fatalf("three credential hits: count = %d, want 0 — at %d the request would be BLOCKED, "+
				"which is exactly the agent-reads-a-config-file case R-compliance-grading-17.S1 forbids", count, escalationMinCount)
		}
		if count >= escalationMinCount {
			t.Fatalf("count %d reaches the escalation threshold %d", count, escalationMinCount)
		}
		// Excluded BY RULE is not the same as unresolvable. A family exclusion
		// must never inflate skipped, or the caller's desync WARN fires on
		// perfectly normal traffic and stops being worth reading.
		if skipped != 0 {
			t.Fatalf("skipped = %d, want 0 — hits excluded by the family rule are working as intended, not desync", skipped)
		}

		// The three findings survive the call unchanged, which is what keeps
		// "三条命中仍各自产生审计事件" true: the counter is a read-only view and
		// the audit path downstream reads the same slice.
		if len(findings[0]) != 3 {
			t.Fatalf("the counter dropped findings: %d left, want 3 — every credential hit must still be audited", len(findings[0]))
		}
		for i, want := range []string{apiKeyA, apiKeyB, apiKeyC} {
			if got, ok := hitValue(pieces[0].text, findings[0][i]); !ok || got != want {
				t.Fatalf("finding %d no longer addresses its own value (got %q ok=%v, want %q) — "+
					"the counter must not rewrite the findings it reads", i, got, ok, want)
			}
			if findings[0][i].Category != "secret" {
				t.Fatalf("finding %d lost its category label", i)
			}
		}
		// And the tool block's action ceiling is untouched: this rule changes
		// whether a hit may be COUNTED, never what may be done to the content.
		if pieces[0].ceiling != ceilingAudit {
			t.Fatalf("the tool block ceiling moved to %v — the family filter must not touch blockScanPolicy", pieces[0].ceiling)
		}
	})

	t.Run("negative control: the same three values under a counted family DO escalate", func(t *testing.T) {
		// Without this half, "count 0" could mean "the family filter works" OR
		// "this fixture never counted anything anyway". Only the pair pins it.
		pieces := toolResultPiece(t, configFile)
		findings := [][]Finding{{
			categorizedHit(t, configFile, apiKeyA, "pii", escalationMinLevel),
			categorizedHit(t, configFile, apiKeyB, "pii", escalationMinLevel),
			categorizedHit(t, configFile, apiKeyC, "pii", escalationMinLevel),
		}}

		count, skipped := countDistinctHits(pieces, findings, escalationMinLevel)
		if count != 3 {
			t.Fatalf("identical fixture under category=pii: count = %d, want 3 — if this is 0 the filter is "+
				"excluding everything, not the secret family", count)
		}
		if skipped != 0 {
			t.Fatalf("skipped = %d, want 0", skipped)
		}
	})

	t.Run("case variants of the label are excluded too", func(t *testing.T) {
		// The built-in packs all write lowercase `secret`, but a tenant-authored
		// pack sets Category from free-form JSON (packs/types.go). A case-only
		// difference silently turning the protection OFF is not an acceptable
		// failure mode for a rule whose whole job is "credentials never assemble
		// a block", and folding case costs one comparison.
		for _, label := range []string{"Secret", "SECRET", "SeCrEt"} {
			t.Run(label, func(t *testing.T) {
				pieces := toolResultPiece(t, configFile)
				findings := [][]Finding{{
					categorizedHit(t, configFile, apiKeyA, label, escalationMinLevel),
					categorizedHit(t, configFile, apiKeyB, label, escalationMinLevel),
					categorizedHit(t, configFile, apiKeyC, label, escalationMinLevel),
				}}
				if count, _ := countDistinctHits(pieces, findings, escalationMinLevel); count != 0 {
					t.Fatalf("category %q: count = %d, want 0 — the family is the same family", label, count)
				}
			})
		}
	})

	t.Run("an unlabelled hit still counts", func(t *testing.T) {
		// The filter is a DENYLIST of one family, not an allowlist of the two or
		// three families anyone happens to remember. The built-in packs already
		// ship six distinct categories (secret / pii / sales_violation /
		// complaint_evasion / internal_sensitive / regulatory_risk), and a pack
		// may add more; an allowlist would silently stop counting every family
		// nobody enumerated. An empty label is the same argument at the limit:
		// unknown must keep counting, or a detector that omits the field
		// disables cumulative escalation wholesale.
		pieces := toolResultPiece(t, configFile)
		findings := [][]Finding{{
			categorizedHit(t, configFile, apiKeyA, "", escalationMinLevel),
			categorizedHit(t, configFile, apiKeyB, "regulatory_risk", escalationMinLevel),
			categorizedHit(t, configFile, apiKeyC, "internal_sensitive", escalationMinLevel),
		}}
		if count, _ := countDistinctHits(pieces, findings, escalationMinLevel); count != 3 {
			t.Fatalf("count = %d, want 3 — only the secret family is excluded; every other label, "+
				"including an absent one, still counts", count)
		}
	})

	t.Run("secret hits do not suppress the PII hits alongside them", func(t *testing.T) {
		// The realistic mixed payload: a config dump that also happens to carry
		// customer identifiers. The credentials drop out; the customer data does
		// not, and the count reflects only the latter.
		const (
			idA = "110101199003071234"
			idB = "310101198807153695"
		)
		mixed := "OPENAI_KEY=" + apiKeyA + "\nnote: customers " + idA + " and " + idB + " both called\nSTRIPE_KEY=" + apiKeyB
		pieces := toolResultPiece(t, mixed)
		findings := [][]Finding{{
			categorizedHit(t, mixed, apiKeyA, "secret", escalationMinLevel),
			categorizedHit(t, mixed, idA, "pii", escalationMinLevel),
			categorizedHit(t, mixed, idB, "pii", escalationMinLevel),
			categorizedHit(t, mixed, apiKeyB, "secret", escalationMinLevel),
		}}

		count, skipped := countDistinctHits(pieces, findings, escalationMinLevel)
		if count != 2 {
			t.Fatalf("count = %d, want 2 (the two ID cards; the two API keys are excluded)", count)
		}
		if count >= escalationMinCount {
			t.Fatalf("count %d must stay below the threshold %d: only two customers are involved", count, escalationMinCount)
		}
		if skipped != 0 {
			t.Fatalf("skipped = %d, want 0", skipped)
		}
	})

	t.Run("an excluded hit is still excluded when it is also unresolvable", func(t *testing.T) {
		// Ordering check: the family filter runs BEFORE the slice attempt, so a
		// credential hit with a broken span is not reported as desync. Getting
		// this backwards would make the caller WARN on traffic the rule already
		// decided to ignore.
		pieces := toolResultPiece(t, configFile)
		findings := [][]Finding{{
			{StartOffset: 0, EndOffset: len(configFile) + 50, Level: escalationMinLevel, Confirmed: true, Category: "secret"},
		}}
		count, skipped := countDistinctHits(pieces, findings, escalationMinLevel)
		if count != 0 || skipped != 0 {
			t.Fatalf("count/skipped = %d/%d, want 0/0 — a hit the family rule excludes never reaches the slice", count, skipped)
		}
	})
}

// TestEscalation_ToolBlockPIICounts guards R-compliance-grading-17.S2: customer
// PII inside a tool block DOES count. This is the half that makes the family
// filter a filter rather than a blanket "tool blocks never escalate".
//
// 🔴 Note what stays put: the block's ceiling is still audit. The rule changes
// whether these hits may be COUNTED toward a request-level verdict, not what may
// be done to this piece of content — see the header note above.
func TestEscalation_ToolBlockPIICounts(t *testing.T) {
	const (
		idA = "110101199003071234"
		idB = "310101198807153695"
		idC = "440305197502289517"
	)
	table := "客户,身份证\n张,\n" + idA + "\n李," + idB + "\n王," + idC + "\n"
	pieces := toolResultPiece(t, table)
	findings := [][]Finding{{
		categorizedHit(t, table, idA, "pii", escalationMinLevel),
		categorizedHit(t, table, idB, "pii", escalationMinLevel),
		categorizedHit(t, table, idC, "pii", escalationMinLevel),
	}}

	count, skipped := countDistinctHits(pieces, findings, escalationMinLevel)
	if count != 3 {
		t.Fatalf("three distinct customer ID cards in a tool_result: count = %d, want 3", count)
	}
	if count < escalationMinCount {
		t.Fatalf("count %d does not reach the escalation threshold %d — the request must be blocked", count, escalationMinCount)
	}
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	if pieces[0].ceiling != ceilingAudit {
		t.Fatalf("the tool block ceiling moved to %v — counting a hit must not raise what may be done to the content", pieces[0].ceiling)
	}
}
