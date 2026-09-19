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

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// Finding is the proxy-side decoded view of one detector finding, holding only
// the fields the request-level counter reads. The findings it decodes are the
// `findings` ARRAY INSIDE the compliance event (apphook.Response.Event, which
// the dispatcher forwards to master verbatim — see injectWireLabels in
// filter_dispatch.go, which reaches the same array as m["findings"]). This type
// is therefore a LOCAL READ VIEW: decoding into it neither reshapes nor filters
// what is uploaded.
//
// 🔴 NOT pipewire.Response.Findings. An earlier version of this comment named
// that field and said the dispatcher forwards it to master; both halves were
// wrong, and the two are 同名异物:
//
//	pipewire.Response.Findings — a per-op payload SLOT on the parent↔child pipe
//	  (masked payload for ActionMask, the canned answer text for ActionAnswer,
//	  a packs report for ListPacks — the full table lives on childResponse in
//	  internal/apphook/childhook.go). It is consumed inside the proxy and is
//	  NEVER uploaded.
//	event.findings[] — part of the audit document, and the thing that IS uploaded.
//
// Corrected 2026-09-14 (task 3.12) because a wrong comment is the next
// implementer's input: task 3.6 was about to build the 代答 text carrier on top
// of this sentence, which would have meant weighing the privacy of a payload it
// believed already traveled to master. 「重名不同义的字段必须写全限定」— hence the
// full qualification above rather than a bare "findings".
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
	// injectWireLabels for the same warning on the labeling join.
	StartOffset int `json:"start_offset"`
	EndOffset   int `json:"end_offset"`
	// Level is the classification level (1..N) resolved from the tenant's
	// classification tree. It is `omitempty` on the wire, so a detector that
	// predates grading — or a finding no leaf claims — decodes to 0, meaning
	// UNGRADED. 0 satisfies no level floor of 1 or higher, which is the
	// intended direction: an ungraded hit never helps reach a stronger action.
	Level int `json:"level"`
	// Category is the FAMILY the matched rule belongs to ("secret" / "pii" /
	// "sales_violation" / ...), taken verbatim from the rule that fired. It is
	// what the family filter below reads; see countsTowardEscalation.
	//
	// 🔴 THIS IS A LABEL, NOT A DERIVATION OF THE CONTENT. It says which rule
	// family matched, and every possible value of it is already written down in
	// the ruleset the tenant installed — it tells an audit reader nothing about
	// WHAT was matched that the rule's own existence does not already tell them.
	// That is precisely why it is allowed here and a hash/fingerprint/snippet is
	// not: those would let someone take a known value, compute the same
	// derivation, and search the audit store for who mentioned it. Adding a
	// field is not the test; "can it be joined back to a content value" is. If
	// the next field you want to add fails that test, it does not belong here
	// regardless of how convenient it would be.
	Category string `json:"category"`
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
// Hits the rules exclude (unconfirmed, below the level floor, or an uncounted
// family) are not skips — they are working as intended and must not raise a WARN
// at the caller. 🔴 That distinction is the whole value of skipped: fold a
// by-design exclusion into it and the caller WARNs on every agent turn that
// reads a config file, at which point nobody reads the WARN any more and the
// real cross-process desync it exists to surface goes back to being invisible.
func countDistinctHits(pieces []contentPiece, findings [][]Finding, minLevel int) (count, skipped int) {
	t := tallyDistinctHits(pieces, findings, minLevel)
	return t.count, t.skipped
}

// hitTally is one pass of the counter. It exists so that the two questions the
// request-level verdict asks — "how many?" and "which pieces?" — are answered by
// ONE traversal with ONE predicate.
//
// 🔴 WHY NOT A SECOND FUNCTION FOR pieceHit: re-deriving "did this piece
// contribute?" at another call site means writing `Confirmed && Level >=
// minLevel && countsTowardEscalation && sliceable` a second time, and the day
// the two spellings disagree the verdict row would name pieces that were not
// counted (or omit ones that were) with nothing going red. countDistinctHits
// keeps its exact signature and behavior on top of this core, so the fences
// task 3.9 wrote still exercise the code that ships.
type hitTally struct {
	// count is the number of DISTINCT values, the input to a rule's min_count.
	count int
	// skipped is the number of hits that passed every rule filter but could not
	// be resolved to a value — see countDistinctHits' contract.
	skipped int
	// pieceHit lists, in piece order, the index of every piece that contributed
	// at least one COUNTED hit. A piece whose only hits were excluded or
	// unresolvable is absent.
	//
	// 🔴 Dedup is by VALUE and therefore GLOBAL, while this list is per PIECE: if
	// the same ID card appears in three pieces the count is 1 and all three
	// pieces are listed. That is intended — the count answers "how many distinct
	// entities", the list answers "which audit rows is this verdict about", and
	// an auditor following the verdict row must reach every row that carried the
	// value, not an arbitrary first one.
	pieceHit []int
}

func tallyDistinctHits(pieces []contentPiece, findings [][]Finding, minLevel int) hitTally {
	var t hitTally
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
		counted := false
		for _, f := range findings[i] {
			// All three exclusions are BY RULE, so they share this one
			// `continue` ahead of any slicing: none of them may land in skipped.
			if !f.Confirmed || f.Level < minLevel || !countsTowardEscalation(f) {
				continue
			}
			if !havePiece {
				t.skipped++
				continue
			}
			value, ok := hitValue(text, f)
			if !ok {
				t.skipped++
				continue
			}
			distinct[value] = struct{}{}
			counted = true
		}
		if counted {
			t.pieceHit = append(t.pieceHit, i)
		}
	}
	t.count = len(distinct)
	return t
}

// categorySecret is the rule family the built-in credential ruleset tags itself
// with — all 224 gitleaks-derived rules in
// ai-compliance-detector/internal/baselines/built-in/credentials.yaml carry it,
// and no other built-in pack does (the other five families there are pii,
// sales_violation, complaint_evasion, internal_sensitive and regulatory_risk).
const categorySecret = "secret"

// countsTowardEscalation reports whether this finding's FAMILY may participate
// in the request-level cumulative count. It is the ONE place that decision is
// made, so that "does a credential hit count?" can never be re-derived by hand
// at a second call site and drift.
//
// spec: R-compliance-grading-17.S1 (agent 读含密钥的配置文件不因累计被拦)
// spec: R-compliance-grading-17.S2 (工具块里的客户 PII 累计触发拦截)
//
// 🔴 WHAT THIS EXCLUDES IS PARTICIPATION IN THE COUNT — NOTHING ELSE. A
// credential hit is still detected, still confirmed, still gets its own audit
// event, and the action ceiling on the block it was found in is untouched
// (that is blockScanPolicy's table, guarded by TestBlockScanPolicy_*). "secret
// 不计入累计" and "secret 不管了" are different sentences and only the first is
// the rule; how a credential itself is handled is that rule's business, not the
// cumulative rule's.
//
// WHY the secret family is the one carved out: the cumulative rule exists to
// catch "one person is pouring out a pile of customer records". An agent
// handing back a config file with three API keys through tool_result is a
// normal working turn. Counting those three would make ordinary development hit
// COMPLIANCE_BLOCKED, and would dismantle from the side the promise on which
// tool blocks were opened for scanning at all in 2026-08-10 — that the
// credential ruleset "永不在 agent 读文件时触发" (bugfix
// 2026-08-10-compliance-tool-result-scan-scope.md). The ceiling stops the
// per-piece action; without this, the cumulative path would reach the same
// outcome by another road.
//
// WHY a DENYLIST of one family rather than an allowlist of the counted ones:
// packs ship tenant-authored families, and the built-ins alone already carry
// six. An allowlist stops counting every family nobody remembered to enumerate
// — silently, and in the permissive direction. Unknown and absent labels
// therefore COUNT. (An ancient detector that emits no category also emits no
// level, so it is already held out by any level floor of 1 or higher.)
//
// WHY case-insensitive: the built-in packs are uniformly lowercase, but
// Category is free-form JSON on a tenant-authored pack (packs/types.go). A
// case-only difference turning this protection off would be silent and would
// fail in the direction this rule exists to prevent. Folding case costs one
// comparison. Note the asymmetry with packs/snapshot.go, which resolves
// Category through an exact-match map: that is a many-to-one dispatch where a
// miss falls back to entity_type, whereas a miss here re-arms a block.
func countsTowardEscalation(f Finding) bool {
	return !strings.EqualFold(f.Category, categorySecret)
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

// ─────────────────────────────────────────────────────────────────────────────
// Request-level evaluation (DEC-compliance-grading-11, step 4)
//
// Everything above answers "how many distinct things did this request contain?".
// Everything below answers "and what does the organisation's policy say to do
// about that number?" — the request-level verdict the dispatcher applies after
// its per-piece loop.
// ─────────────────────────────────────────────────────────────────────────────

// EscalationRule is one entry of the org grading document's `escalation[]`
// array: "≥ MinLevel 的已确认命中达到 MinCount 条 → Action".
//
// The three JSON keys are taken VERBATIM from design §4b.1
// (`escalation []{min_level int, min_count int, action string}`), which is the
// same document master stores and the console edits. Unknown members of the
// document are the customer's own and pass through untouched — this type is a
// READER and is never marshaled back (the same posture as the detector's
// actionpolicy.Grading and master's compliance.GradingDocument; a partial writer
// deletes what it has not learned yet).
//
// 🔴 THE DOMAIN OF `action` IS HELD HERE OR NOWHERE. master validates the
// document's SHAPE only and explicitly leaves each member's contents to its
// owning task (grading_document.go: 「Validating the ladder's contents … belongs
// to the grading validation task」), and `escalation` is owned by the proxy. A
// value this side cannot enact is therefore not caught anywhere else — see
// escalationEnactableAction.
type EscalationRule struct {
	MinLevel int    `json:"min_level"`
	MinCount int    `json:"min_count"`
	Action   string `json:"action"`
}

// String renders the rule for the audit record (`escalation.rule` on the request
// verdict event) and for logs.
//
// 🔴 CONFIG ONLY, NEVER CONTENT. Every part of this string comes from the
// document an administrator saved; nothing in it derives from what was matched.
// That is what makes it safe to put on the wire (R-compliance-grading-16), and
// it is why the audit page can show an administrator WHICH rule fired without
// showing them anything about the prompt.
func (r EscalationRule) String() string {
	return "level>=" + itoaInt64(int64(r.MinLevel)) +
		",count>=" + itoaInt64(int64(r.MinCount)) +
		",action=" + r.Action
}

// escalationEnactableAction is THE single place that decides which
// `escalation[].action` spellings this proxy can actually carry out at REQUEST
// level, and it deliberately admits exactly one today.
//
// WHY ONLY `block`, spelled out so the next reader does not "restore" the others:
//
//   - mask / warn / audit / allow are PER-PIECE outcomes. By the time the
//     request-level verdict runs, every piece has already been given its ladder
//     action and the masks are written; there is no request-level act of masking
//     left to perform, and a rule that resolves to one of them could only ever be
//     weaker than what already happened — which R-compliance-grading-15 forbids
//     ("SHALL NOT 弱于逐片段动作的最强项"). Silently treating it as a no-op would
//     leave an administrator staring at a configured control that does nothing.
//   - answer (代答) needs an administrator-authored SENTENCE, and every tier of
//     the three-tier fallback that produces one is resolved per FINDING inside
//     the detector (actionpolicy.ResolveAnswerText). A request-level conclusion
//     belongs to no finding, so there is no text to serve; synthesizing a 200
//     with an empty body is exactly the failure R-compliance-canned-answer-2.S2
//     rules out. It is REJECTED rather than degraded to a silent block because
//     the administrator asked for a friendly refusal and must be told they are
//     not getting one.
//
// A rejected rule is DROPPED and named in a WARN at install time (see
// parseEscalationRules → the supervisor's log line), which is the same posture
// the detector takes for an unreadable ladder rung (「org ladder rung declares an
// unknown action; enforcement left unchanged」, actionpolicy.AdminDeclaredAction).
// Inventing a strong action out of a typo is the alternative, and it turns one
// misspelled word in a console field into a fleet-wide outage.
func escalationEnactableAction(name string) (apphook.Action, bool) {
	switch name {
	case "block":
		return apphook.ActionBlock, true
	default:
		return apphook.ActionAllow, false
	}
}

// requestEscalationCeiling is the REQUEST-level action ceiling the escalated
// verdict is clamped by (R-compliance-grading-15: 「升级后的动作 SHALL 受请求级
// 天花板（MAX_ACTION / audit_only 包 / 许可）钳制」).
//
// 🔴 IT IS NOT DERIVED FROM THE PIECES, AND THAT IS THE WHOLE POINT. The
// per-piece ceiling answers "what may be done to THIS content" (a tool block is
// capped at audit); the request-level ceiling answers "what may be done to this
// REQUEST". They are two axes — R-compliance-grading-17 says so in as many
// words, and R-compliance-grading-17.S2 pins the consequence: a request whose
// only content is an audit-capped tool block MUST still be refusable when three
// customer records accumulate inside it. Taking the minimum (or the maximum) of
// the piece ceilings here would make that scenario impossible to satisfy.
//
// WHERE EACH OF THE THREE RUNGS THE RULE NAMES IS ENFORCED:
//
//   - MAX_ACTION — HERE. The detector child caps each piece at it
//     (actionpolicy.capRuntimeAction); only this process can cap the cumulative
//     verdict, because only this process forms it. The value arrives through
//     SetComplianceMaxAction, fed by the supervisor with the SAME variable it
//     bakes into AIKEY_COMPLIANCE_FILTER_MAX_ACTION (internal/supervisor/
//     filter_hook.go; fence TestEscalation_MaxActionReachesProxyFromSupervisor).
//   - audit_only pack — caps at source, inside the detector.
//   - licensing — gates the filter's existence rather than its verdicts.
//
// Until task 3.13 this was the constant ceilingFull, and an operator's
// MAX_ACTION=warn — set precisely to stop refusals during a rollout window —
// did not reach the cumulative rule, which kept refusing whole requests.
//
// It stays a single NAMED accessor rather than an expression at the call site so
// the concept has exactly one place, instead of being re-derived by hand at
// whichever call site notices first.
func (p *Proxy) requestEscalationCeiling() actionCeiling {
	c, _ := requestCeilingForMaxAction(p.complianceMaxAction)
	return c
}

// requestCeilingForMaxAction is the ONE place a MAX_ACTION value is paired with
// the request-level ceiling it imposes — the same shape as toolBlockCeilingFor.
// Its domain is exactly actionpolicy.ParseMaxAction's: "" and "full" are full,
// "warn" is warn, anything else is not a value.
//
// 🔴 warn MAPS TO ceilingWarn, NEVER TO ceilingAudit. Both let the request
// through, but audit turns the escalated block into ALLOW — "warn the operator"
// silently becomes "nothing happened", the opposite of the detector's own
// reading of the same setting (capRuntimeAction: block → warn). Fence:
// TestEscalation_MaxActionWarnCapsEscalatedBlock, whose ceilingAudit-trap
// assertion goes red on exactly that substitution.
//
// ok=false for an unrecognized value. The ceiling returned alongside it is
// never used for enforcement: SetComplianceMaxAction refuses such a value
// before it can be stored.
func requestCeilingForMaxAction(maxAction string) (actionCeiling, bool) {
	switch maxAction {
	case "", "full":
		return ceilingFull, true
	case "warn":
		return ceilingWarn, true
	default:
		return ceilingFull, false
	}
}

// escalationOutcome is what the request-level verdict concluded.
//
// 🔴 IT IS A STRUCT, AND THAT IS A DELIBERATE DEVIATION from the two-value
// signature the task text asked for ((Action, *EscalationRule)). Those two
// values cannot carry the two numbers the callers are REQUIRED to have:
//
//   - Skipped, which task 3.9 handed over in writing — countDistinctHits is a
//     pure function with no request context, so the WARN about a detector/proxy
//     desync 「MUST be raised by the caller」, and a caller that never receives
//     the number cannot raise it;
//   - Counted and UnitIDs, which R-compliance-grading-18 requires on the request
//     verdict event (`escalation{rule, counted, unit_ids}`).
//
// Returning them through package state or recomputing them at the call site were
// the alternatives; both mean two answers to one question. The two values the
// task named are still here, under their own names.
type escalationOutcome struct {
	// Rule is the rule that fired, or nil when none did. Nil is the overwhelming
	// common case (no org policy) and it is what "no escalation" means.
	Rule *EscalationRule
	// Action is the escalated verdict AFTER the request-level ceiling, or
	// ActionAllow when nothing fired. ActionAllow never means "allow this
	// request" — the per-piece outcomes already decided that; it means "the
	// cumulative rule adds nothing".
	Action apphook.Action
	// Counted is the distinct-hit count of the rule that FIRED. It is the number
	// the audit row reports, so it must be the number the decision was made on —
	// never a recount at the call site.
	//
	// When no rule fired it is the LARGEST count any pass produced, i.e. how
	// close the request came. That distinction is what lets a reader tell "every
	// hit was excluded" (0) apart from "two hits, threshold three" (2) — the
	// second is a working control, the first is often a mis-labeled ruleset.
	// With no rules configured at all there is no pass and it is 0.
	Counted int
	// Skipped is the largest number of unresolvable hits any counting pass saw.
	// 🔴 MAX, NOT SUM: every rule re-examines the SAME findings, so summing would
	// multiply one desynced hit by the number of configured rules and make the
	// WARN's number meaningless. The lowest level floor sees a superset of what
	// every higher floor sees, so the maximum is the honest "at least this many
	// hits could not be resolved".
	Skipped int
	// Units are the INDEXES of the pieces that contributed at least one counted
	// hit, in piece order. The caller turns them into the audit-unit ids the
	// verdict event lists (R-compliance-grading-18: 「关联走该列表，不依赖
	// trace_id」).
	//
	// 🔴 Indexes, not ids: this function must not learn what an audit unit id is
	// — that is a dispatcher-side concept built from the cache scope and the
	// content hash. It reports WHICH pieces were counted; the caller, which
	// already minted one id per piece, does the join.
	Units []int
	// Capped reports that the request-level ceiling downgraded the escalated
	// action, so the caller can keep the audit record truthful the same way the
	// per-piece path does.
	Capped bool
}

// evaluateEscalation is the request-level verdict: it turns N per-piece finding
// lists plus the org's escalation rules into one conclusion about the whole
// request.
//
// findings[i] belongs to pieces[i]; a nil row means "this piece produced no
// findings the proxy could read" (see decodeEventFindings).
//
// spec: R-compliance-grading-15 (累计升级在片段循环后做请求级判定)
//
// WHY IT IS A PURE FUNCTION over its four inputs, given the dispatcher could
// just as well have done this inline: the whole cumulative rule is "look at the
// request as a whole", and the request as a whole is precisely what the piece
// loop cannot see. Keeping the conclusion in one function with no request
// context makes it testable against a table of finding sets, which is how the
// counting half is fenced too.
//
// SELECTION when several rules fire: the FIRST one in document order wins.
// 🔴 That is only correct while escalationEnactableAction admits a single
// action — every rule that fires then concludes the same thing and the choice is
// cosmetic (which rule the audit row names). The moment a second enactable
// action exists, this needs a strength ordering, and
// TestEscalation_EnactableActionSetIsSingular goes red to say so.
func evaluateEscalation(pieces []contentPiece, findings [][]Finding, rules []EscalationRule, ceiling actionCeiling) escalationOutcome {
	var out escalationOutcome
	out.Action = apphook.ActionAllow
	for i := range rules {
		rule := rules[i]
		tally := tallyDistinctHits(pieces, findings, rule.MinLevel)
		if tally.skipped > out.Skipped {
			out.Skipped = tally.skipped
		}
		if out.Rule != nil {
			continue // already concluded; keep counting only for the skip signal
		}
		if tally.count < rule.MinCount {
			// Report the closest any rule came, so an operator (and a fence) can
			// tell "the family filter excluded everything" (0) from "it counted
			// but did not reach the threshold" (n) — two very different states
			// that a bare "no escalation" collapses into one.
			if tally.count > out.Counted {
				out.Counted = tally.count
			}
			continue
		}
		action, ok := escalationEnactableAction(rule.Action)
		if !ok {
			// Unreachable through parseEscalationRules, which drops these at
			// install time. Kept as the fail-safe half of that gate: a rule that
			// reached here with an action nobody can enact must not silently
			// become "block" — it must do nothing, exactly as the install-time
			// rejection promised the operator.
			continue
		}
		out.Rule = &rules[i]
		out.Counted = tally.count
		out.Action, out.Capped = ceiling.clamp(action)
		out.Units = tally.pieceHit
	}
	return out
}

// decodeEventFindings pulls the `findings` array out of ONE detector compliance
// event so the request-level counter can read it.
//
// 🔴 WHAT IT DECODES, precisely: the `findings` array inside the compliance
// EVENT — the same array injectWireLabels reaches as m["findings"], and the same
// bytes the dispatcher forwards to master untouched. Decoding here neither
// reshapes nor filters what is uploaded; it is a read-only view (see the Finding
// type's header, corrected 2026-09-14, for the field this used to be confused
// with).
//
// 🔴 `category` COMES ALONG BECAUSE Finding DECLARES IT, and that is load
// bearing: without it every finding reads category "" , countsTowardEscalation
// never excludes anything, and credential hits start assembling blocks — with no
// error anywhere. The wire is verified to carry it: the detector stamps
// Category unconditionally (cmd/detector/main.go emitEvent, `intake.Finding
// .Category` has NO omitempty) and every hop in this proxy moves the event as
// `map[string]json.RawMessage`, which cannot drop a member it does not model.
// Fence: TestEscalation_CountsAcrossPieces' secret sub-case, which blocks if the
// label goes missing.
//
// Fail-safe, like the inject* family it mirrors: anything unparseable yields no
// findings rather than an error. A malformed event is already the detector's bug
// and it still travels to master intact; failing the user's request over it
// would turn a reporting defect into an outage (§6 #11).
//
// PERSONAL ROUTES (TODO-87, 2026-09-15 — this paragraph used to say personal
// routes decode to nothing and never escalate; that limit is closed). On a
// personal route apphook.Response.Event is a pipewire.CountProjection: the
// detector has already uploaded the full event to the local self-view and hands
// the proxy only `event_id` + `findings[]{start_offset, end_offset, level,
// category, confirmed}`. Those keys are a subset of a team event's, so THIS one
// reader serves both routes and the two cannot count differently. Event is still
// empty on a personal route when the org has no grading document (nothing to
// count) or the detector predates TODO-87 (the dispatcher WARNs on that).
// spec: R-compliance-grading-15 (累计升级在片段循环后做请求级判定 — now on both routes)
func decodeEventFindings(eventJSON []byte) []Finding {
	if len(eventJSON) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &m); err != nil {
		return nil
	}
	raw, ok := m["findings"]
	if !ok {
		return nil
	}
	var findings []Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil
	}
	return findings
}

// decodeEventID reads `event_id` out of a personal-route count projection
// (pipewire.CountProjection) — the id of the content row the DETECTOR uploaded
// to the local self-view for this piece.
//
// It is the personal route's counterpart of auditUnitID: on a team route the
// proxy mints the row id itself (content-derived) because it uploads the row; on
// a personal route it uploads nothing, so the only id that names an existing row
// is the one the detector already used. The request-verdict row lists these ids
// in escalation.unit_ids (R-compliance-grading-18: 「关联走该列表」), so using any
// other value would leave every entry pointing at nothing.
//
// Fail-safe like decodeEventFindings: unreadable ⇒ "". An empty id is skipped
// when the verdict row's list is built, never invented.
func decodeEventID(eventJSON []byte) string {
	if len(eventJSON) == 0 {
		return ""
	}
	var head struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(eventJSON, &head); err != nil {
		return ""
	}
	return head.EventID
}

// notePersonalProjectionState surfaces, on the transition only, that a
// personal-route request could not be fully counted because the detector handed
// back no count projection for some flagged pieces (TODO-87 BUT NOT: 探测器过旧
// 不回传投影时只告警不拦截).
//
// withProjection / withoutProjection count THIS request's pieces: a piece with a
// projection, and a flagged (non-allow) piece without one. With no escalation
// rules installed there is nothing to under-enforce and it stays silent — the
// Personal edition and orgs without rules must see no new log line.
//
// WHY THE LATCH: an un-upgraded detector stays un-upgraded, so a per-request
// line would emit at request rate until someone upgrades — the same reasoning as
// noteVerdictCacheState. Called from the dispatcher with the REQUEST logger so
// the WARN carries request_id / trace_id / span_id (日志规范).
func (p *Proxy) notePersonalProjectionState(logger *slog.Logger, withProjection, withoutProjection int) {
	if len(p.escalationRules) == 0 {
		return
	}
	if withoutProjection > 0 {
		if p.personalProjectionMissing.CompareAndSwap(false, true) {
			logger.Warn("filter: personal-route pieces were flagged but the detector returned no count projection; "+
				"they do NOT count toward the organization's cumulative escalation rule (upgrade the detector)",
				"event.name", observability.EventProxyFilterPersonalProjectionMissing,
				"pieces_without_projection", withoutProjection,
				"pieces_with_projection", withProjection,
				"rules", len(p.escalationRules))
		}
		return
	}
	if withProjection > 0 && p.personalProjectionMissing.CompareAndSwap(true, false) {
		logger.Info("filter: personal-route count projections are arriving again; cumulative escalation counts "+
			"personal-key traffic",
			"event.name", observability.EventProxyFilterPersonalProjectionRestored,
			"pieces_with_projection", withProjection)
	}
}

// parseEscalationRules reads `escalation[]` out of the org grading document the
// master handed down (the same bytes the supervisor bakes into the detector's
// AIKEY_COMPLIANCE_GRADING env — one document, two readers, each modeling only
// its own member).
//
// It returns the rules this proxy can enact and, separately, a human-readable
// line per rule it REFUSED. Refusals are returned rather than logged here for
// the same reason countDistinctHits returns `skipped`: this is a pure function
// with no logger and no request context, and the caller has both.
//
// An empty document, `{}`, or an absent/empty `escalation` member all mean "no
// cumulative rule configured" and are NOT errors — an org that never opened
// grading must keep behaving exactly as it did before this feature
// (R-compliance-grading-3.S1).
//
// WHY min_count < 1 IS REFUSED: `{"min_count":0}` — the shape a forgotten field
// produces — would make `count >= min_count` true on every request, including
// one with no findings at all, and block the entire organisation's traffic. A
// zero threshold is never a meaningful policy, so the only question is whether
// the operator finds out from a WARN or from their users.
func parseEscalationRules(gradingJSON []byte) (rules []EscalationRule, refused []string, err error) {
	if len(bytes.TrimSpace(gradingJSON)) == 0 {
		return nil, nil, nil
	}
	var doc struct {
		Escalation []EscalationRule `json:"escalation"`
	}
	if err := json.Unmarshal(gradingJSON, &doc); err != nil {
		return nil, nil, fmt.Errorf("compliance grading policy: escalation: %w", err)
	}
	for _, r := range doc.Escalation {
		switch {
		case r.MinCount < 1:
			refused = append(refused, r.String()+" (min_count must be at least 1; a zero threshold "+
				"fires on every request, including empty ones)")
		case r.MinLevel < 0:
			refused = append(refused, r.String()+" (min_level must not be negative)")
		default:
			if _, ok := escalationEnactableAction(r.Action); !ok {
				refused = append(refused, r.String()+" (only `block` can be enacted as a "+
					"request-level verdict; see escalationEnactableAction)")
				continue
			}
			rules = append(rules, r)
		}
	}
	return rules, refused, nil
}

// escalationMetrics counts what the request-level verdict did, per generation.
//
// WHY COUNTERS AND NOT JUST LOG LINES: R-compliance-grading-15.S2 demands an
// assertion that the verdict path 「已执行且结论为『无升级』」 — i.e. the fence has
// to distinguish "evaluated and concluded nothing" from "never ran". Log lines
// cannot express the first case without printing one per request, and a fence
// built on log scraping breaks the moment the wording changes.
//
// Counts only — never a value, a rule body, or anything content-derived.
type escalationMetrics struct {
	// evaluated: request-level verdicts run (one per filterable request that
	// reached the piece loop).
	evaluated atomic.Int64
	// triggered: verdicts where a rule fired.
	triggered atomic.Int64
	// lastCounted: the distinct-hit count of the most recent evaluation. A
	// last-value gauge rather than a sum on purpose — a sum answers no question
	// an operator asks, while "what did the last request count" is exactly what a
	// fence and a support engineer both need.
	lastCounted atomic.Int64
	// unresolvedHits: hits that passed every rule filter but could not be sliced
	// (see countDistinctHits' `skipped`). A rising number means the detector's
	// offsets and the proxy's text disagree — a cross-process desync.
	unresolvedHits atomic.Int64
	// evaluatedOnTruncated: verdicts reached on a request in which at least one
	// content piece was cut at pipeInputCap (TODO-72). On those requests the
	// detector never saw the tail, so `lastCounted` is a LOWER BOUND and a
	// request that should have escalated may have been let through. This is a
	// declared blind spot (DEC-compliance-grading-26), not a fault — the number
	// exists so an operator can see how often a verdict was reached on
	// incomplete input instead of inferring it from silence.
	evaluatedOnTruncated atomic.Int64
}

// escalationSnapshot is a consistent-enough read of the counters for fences and
// support. Cheap; safe during concurrent request processing.
func (p *Proxy) escalationSnapshot() struct {
	evaluated  int
	triggered  int
	counted    int
	unresolved int
} {
	return struct {
		evaluated  int
		triggered  int
		counted    int
		unresolved int
	}{
		evaluated:  int(p.escalationMetrics.evaluated.Load()),
		triggered:  int(p.escalationMetrics.triggered.Load()),
		counted:    int(p.escalationMetrics.lastCounted.Load()),
		unresolved: int(p.escalationMetrics.unresolvedHits.Load()),
	}
}
