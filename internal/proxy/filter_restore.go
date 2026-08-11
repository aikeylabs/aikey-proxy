// filter_restore.go — B3 restorable-mask renumbering (request leg) + placeholder
// restoration (response leg, non-streaming). SSE streaming restoration lives in
// sse_restore.go.
//
// Chain (B3, 拍板 2026-08-06 + spec 2026-06-04 规则 2 唯一例外):
//
//	detector masks a restorable span with a NUMBERLESS token (e.g. 地址 →
//	"{{ADDR}}") and ships the replaced spans (offsets only) over the v4
//	pipe → applyInboundFilter renumbers each token occurrence into a
//	per-request label `prefix+N+suffix` (e.g. "{{ADDR_1}}") and records
//	label→original in a *maskRestore hung on the request context → the
//	response leg swaps any label the LLM echoed back to the original text.
//
// WHY the proxy renumbers (not the detector): the detector child sees one
// content piece per Detect call and has no request scope — "同请求内按出现顺序
// 编号" is only computable here. WHY occurrence-order + count validation: the
// masked text is the only truth for where tokens ended up after the planner's
// overlap resolution; a count mismatch (e.g. the user literally typed the
// token) makes the alignment ambiguous, so we keep the (safe) numberless mask
// and skip restore rather than risk mapping a label to the wrong original.
//
// P2 (方案 20260808 §3.2 L3 / §3.3, 2026-08-08) added three things on top:
//
//  1. MULTI-TOKEN correctness. P1 generalized the detector to emit ONE
//     Restorable per entity family, so a single request now routinely carries
//     `{{ADDR}}` + `{{PHONE}}` + `{{EMAIL}}`. Two latent bugs that a single
//     restorable could never trip became reachable: the numbered prefix/suffix
//     was picked by a linear scan keyed on Token (串味 across families), and
//     each token was counted with an independent substring search (a token that
//     is a substring of another token double-counts). See scanTokenOccurrences.
//  2. L3 fault-tolerant restore. LLMs echo the placeholder back with cosmetic
//     drift (`{{ ADDR_1 }}`, `{ADDR_1}`, `{{addr_1}}`, quoted). The response leg
//     therefore matches a TOLERANT pattern for the shipped `{{CODE_N}}` shape —
//     but resolves it strictly through the per-request table: an ID that is not
//     in the table is left VERBATIM (不变量 §5.2 永不猜测、永不模糊映射).
//  3. Fidelity health signal. `maskFidelity` counts placeholders issued on the
//     request leg vs DISTINCT placeholders restored on the response leg; the
//     ratio is the externally-readable "is the model still preserving our
//     placeholders?" signal exposed on /v1/diagnostics/pipeline.
//
// 🚫 PRIVACY INVARIANT (B3 拍板): the placeholder↔original mapping is
// per-request memory ONLY — it must never be persisted, uploaded, or written
// to any log (originals are exactly the sensitive spans the mask hid). Log
// lines in this file carry counts/lengths, never content. The fidelity counters
// are COUNTS ONLY and deliberately carry no label, no code and no text.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// maskFidelity is the process-wide L3 保真率 counter pair (方案 §3.2 L3:
// "健康指标=发出占位符数 vs 还原成功数，保真率下降即说明某模型开始改写").
//
// Issued counts every per-request label the proxy substituted into a forwarded
// prompt. Restored counts every label that came BACK from the model and was
// swapped to the original — counted at most ONCE per label per request (a model
// that repeats `{{ADDR_1}}` five times must not push the ratio above 100%),
// which is what makes Restored/Issued readable as a fidelity percentage.
//
// Counts only: never a label, a code, a length or any text (privacy invariant).
type maskFidelity struct {
	issued   atomic.Int64
	restored atomic.Int64
}

// Placeholder syntax constants — the ONLY place the proxy spells out the shipped
// `{{CODE_N}}` shape. The detector's planner.NewLabel owns the same knowledge on
// its side (single source of truth per process, mirrored by the v4 wire, which
// carries prefix/suffix explicitly so an operator's custom label keeps working
// through the exact-match path below).
var (
	// canonicalLabelRe recognizes a label the proxy just emitted as belonging to
	// the shipped `{{CODE_N}}` family, which is what makes it eligible for the
	// tolerant response-leg matcher. Custom operator labels (e.g. `[ADDR#1-X]`)
	// simply do not match and fall back to byte-exact restore.
	canonicalLabelRe = regexp.MustCompile(`^\{\{([A-Za-z][A-Za-z0-9]*)_(\d{1,9})\}\}$`)

	// tolerantPlaceholderRe is the L3 matcher (方案 §3.2 L3). It accepts the
	// cosmetic drift LLMs actually introduce, each variant bounded so the SSE
	// holdback window stays finite:
	//   - single braces:            {ADDR_1}
	//   - one space in each slot:   {{ ADDR _ 1 }}
	//   - any case:                 {{addr_1}} / {{Addr_1}}
	//   - quotes INSIDE the braces: {{"ADDR_1"}} (outside-the-braces quoting
	//     needs no support — the placeholder itself still matches).
	// It deliberately does NOT accept an arbitrary run of whitespace: an
	// unbounded variant would make the streaming holdback window unbounded too.
	// Matching is only the FIRST half of restore — the captured code+number must
	// still resolve in the per-request table or the match is left untouched.
	tolerantPlaceholderRe = regexp.MustCompile(
		`\{\{?[ \t]?["'` + "`" + `\x{201C}\x{2018}]?[ \t]?([A-Za-z][A-Za-z0-9]*)[ \t]?_[ \t]?([0-9]{1,9})[ \t]?["'` + "`" + `\x{201D}\x{2019}]?[ \t]?\}?\}`)

	// tolerantPlaceholderPrefixRe is tolerantPlaceholderRe with every element
	// made optional and the whole thing anchored: it matches exactly the set of
	// PREFIXES of a tolerant placeholder. Used by the SSE holdback to decide
	// whether a trailing `{…` may still grow into one. Derived from the pattern
	// above — keep the two in sync (fenced by TestMaskRestore_HoldbackTolerant*).
	tolerantPlaceholderPrefixRe = regexp.MustCompile(
		`^\{\{?[ \t]?["'` + "`" + `\x{201C}\x{2018}]?[ \t]?(?:[A-Za-z][A-Za-z0-9]*)?[ \t]?(?:_[ \t]?[0-9]{0,9}[ \t]?["'` + "`" + `\x{201D}\x{2019}]?[ \t]?\}?)?$`)
)

// tolerantHoldbackSlack is how many bytes a tolerant variant may exceed the
// canonical label it stands for: 5 optional single spaces + 2 quote characters
// (≤3 bytes each for the curly Unicode ones) = 11, rounded up to 16 for margin.
// The SSE holdback window is widened by this so a placeholder split across
// delta frames is still re-assembled when the model added spaces/quotes.
const tolerantHoldbackSlack = 16

// maskRestore is the per-request placeholder→original state. Built on the
// request leg, consumed on the response leg. The request leg finishes all
// writes before the response leg reads (the ReverseProxy round-trip strictly
// follows applyInboundFilter), so only the fidelity bookkeeping — the one thing
// a future second response-side consumer could touch concurrently — is locked.
type maskRestore struct {
	entries map[string]string // numbered label → original text (ALL shapes)
	// canonical maps the normalized id of a shipped `{{CODE_N}}` label
	// (UPPERCASE code + "_" + number without leading zeros) to its original.
	// This — not a regex over the response — is the authority the L3 tolerant
	// matcher resolves against: a miss means "leave verbatim" (不变量 §5.2).
	canonical map[string]string
	// custom holds labels that are NOT of the shipped shape (operator override
	// via mask_labels / the legacy address_mask_label). They get byte-exact
	// restore only: the proxy cannot invent a tolerant grammar for a string it
	// does not own.
	custom []string
	// restoredIDs de-duplicates the fidelity accounting (see maskFidelity).
	restoredIDs map[string]bool
	fid         *maskFidelity     // nil in unit tests / when no proxy is wired
	keys        []string          // labels in allocation order (for prefix holdback)
	replacer    *strings.Replacer // custom-label replacer, built lazily
	mu          sync.Mutex        // guards restoredIDs only
	maxKeyLen   int               // longest label byte length (SSE holdback window base)
	nextN       int               // next label number (starts at 1)
}

func newMaskRestore() *maskRestore {
	return &maskRestore{entries: make(map[string]string), nextN: 1}
}

func (st *maskRestore) add(label, original string) {
	st.entries[label] = original
	st.keys = append(st.keys, label)
	if len(label) > st.maxKeyLen {
		st.maxKeyLen = len(label)
	}
	if m := canonicalLabelRe.FindStringSubmatch(label); m != nil {
		if st.canonical == nil {
			st.canonical = make(map[string]string)
		}
		st.canonical[canonicalID(m[1], m[2])] = original
	} else {
		st.custom = append(st.custom, label)
	}
	if st.fid != nil {
		st.fid.issued.Add(1)
	}
}

// canonicalID normalizes a code+number pair into the lookup key: codes are
// case-folded (the model may lowercase them) and the number loses leading zeros
// (`{{ADDR_01}}` and `{{ADDR_1}}` are the same placeholder). Normalization is
// EXACT, never fuzzy — it maps two spellings of the SAME id together and never
// bridges two different ids.
func canonicalID(code, number string) string {
	n := strings.TrimLeft(number, "0")
	if n == "" {
		n = "0"
	}
	return strings.ToUpper(code) + "_" + n
}

// rep returns the custom-label→original replacer (built once; the request leg
// is done mutating by the time the response leg calls this).
func (st *maskRestore) rep() *strings.Replacer {
	if st.replacer == nil {
		pairs := make([]string, 0, len(st.custom)*2)
		for _, k := range st.custom {
			pairs = append(pairs, k, st.entries[k])
		}
		st.replacer = strings.NewReplacer(pairs...)
	}
	return st.replacer
}

// restore swaps placeholders in s back to their originals.
//
// Two passes, in this order and for this reason:
//  1. the L3 tolerant pass over the shipped `{{CODE_N}}` family. It also covers
//     the byte-exact spelling (a subset of the tolerant pattern), and — because
//     it never re-scans the text it just inserted — an original that happens to
//     contain placeholder-looking text can never be restored a second time.
//  2. the byte-exact replacer for operator-custom labels, skipped entirely in
//     the shipped configuration (no custom labels → single pass).
func (st *maskRestore) restore(s string) string {
	if len(st.keys) == 0 || s == "" {
		return s
	}
	out := s
	if len(st.canonical) > 0 && strings.IndexByte(out, '{') >= 0 {
		out = st.restoreCanonical(out)
	}
	if len(st.custom) > 0 {
		for _, k := range st.custom {
			if strings.Contains(out, k) {
				st.markRestored(k)
			}
		}
		out = st.rep().Replace(out)
	}
	return out
}

// restoreCanonical is the L3 fault-tolerant half. Every regex hit is resolved
// through st.canonical; a MISS is copied through byte-for-byte.
//
// 🔴 不变量 §5.2 lives here: an unknown id is never mapped to "the nearest"
// entry, never to the only entry, never to anything. The user sees the
// placeholder — 失败要显眼 — instead of another person's address.
func (st *maskRestore) restoreCanonical(s string) string {
	locs := tolerantPlaceholderRe.FindAllStringSubmatchIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var sb strings.Builder
	last := 0
	for _, m := range locs {
		id := canonicalID(s[m[2]:m[3]], s[m[4]:m[5]])
		orig, ok := st.canonical[id]
		if !ok {
			continue // unknown id → leave the bytes exactly as the model wrote them
		}
		sb.WriteString(s[last:m[0]])
		sb.WriteString(orig)
		last = m[1]
		st.markRestored(id)
	}
	if last == 0 {
		return s // nothing resolved — hand back the original string, no copy
	}
	sb.WriteString(s[last:])
	return sb.String()
}

// markRestored records the first successful restore of one placeholder id in
// this request and bumps the process-wide fidelity counter accordingly.
func (st *maskRestore) markRestored(id string) {
	if st.fid == nil {
		return
	}
	st.mu.Lock()
	if st.restoredIDs == nil {
		st.restoredIDs = make(map[string]bool)
	}
	if st.restoredIDs[id] {
		st.mu.Unlock()
		return
	}
	st.restoredIDs[id] = true
	st.mu.Unlock()
	st.fid.restored.Add(1)
}

// holdback returns the trailing bytes an SSE restorer must withhold until the
// next frame because they may be the beginning of a placeholder that got split
// across frames. Two independent detectors, longest answer wins:
//
//   - exact: the longest proper suffix of s that is a strict prefix of a known
//     label (covers custom labels and the byte-exact shipped spelling);
//   - tolerant: an unterminated `{`-run that could still grow into a tolerant
//     `{{CODE_N}}` variant (covers the spaced/quoted/single-brace forms, which
//     are longer than the label itself — hence tolerantHoldbackSlack).
//
// Both are bounded by the window, so withholding can never stall a stream: the
// held bytes are prepended to the next text frame and flushed before any
// boundary frame / EOF regardless.
func (st *maskRestore) holdback(s string) string {
	hold := st.holdbackExact(s)
	if len(st.canonical) > 0 {
		if h := st.holdbackTolerant(s); len(h) > len(hold) {
			hold = h
		}
	}
	return hold
}

func (st *maskRestore) holdbackExact(s string) string {
	maxHold := st.maxKeyLen - 1
	if maxHold > len(s) {
		maxHold = len(s)
	}
	for l := maxHold; l > 0; l-- {
		suf := s[len(s)-l:]
		for _, k := range st.keys {
			if len(k) > l && strings.HasPrefix(k, suf) {
				return suf
			}
		}
	}
	return ""
}

// holdbackTolerant withholds a trailing `{…` run that is still a VIABLE PREFIX
// of a tolerant placeholder — i.e. the model may be halfway through writing one
// and the rest arrives in the next delta frame.
//
// Viability is decided by tolerantPlaceholderPrefixRe: the tolerant grammar
// with every trailing element made optional, anchored, so it accepts exactly
// "some prefix of a tolerant placeholder" and nothing else. That precision is
// the point — a character-class heuristic would withhold the `{` of every JSON
// or code block a model streams back, turning the byte-identical passthrough
// into a re-encode for a whole class of ordinary answers.
func (st *maskRestore) holdbackTolerant(s string) string {
	window := st.maxKeyLen + tolerantHoldbackSlack - 1
	if window > len(s) {
		window = len(s)
	}
	tail := s[len(s)-window:]
	// EARLIEST viable `{` in the window, not the last one: `{{ad` must be held
	// whole — starting at the second brace would emit the first one and the
	// placeholder could never be re-assembled on the next frame.
	for i := 0; i < len(tail); i++ {
		if tail[i] != '{' {
			continue
		}
		if tolerantPlaceholderPrefixRe.MatchString(tail[i:]) {
			return tail[i:]
		}
	}
	return ""
}

// maskRestoreFromContext returns the request's restore state, or nil (the
// overwhelmingly common case: no restorable mask this request → response leg
// pays a single nil check).
func maskRestoreFromContext(ctx context.Context) *maskRestore {
	st, _ := ctx.Value(ctxKeyMaskRestore).(*maskRestore)
	if st == nil || len(st.keys) == 0 {
		return nil
	}
	return st
}

// scanTokenOccurrences locates the occurrences of EVERY token in one left→right
// pass over s, longest-match-wins, and returns them keyed by token.
//
// WHY not one independent strings.Index loop per token (the pre-P2 shape): if
// token A is a substring of token B, A's independent scan also lands inside
// every B occurrence. Those phantom hits are not harmless — when the phantom
// count happens to equal A's real span count, the alignment check passes and
// the renumberer writes A's label INTO the middle of a B token, corrupting B
// and mapping one of A's originals onto text that was never A's. Silent
// mis-restore, exactly what 不变量 §5.2 forbids.
//
// P1 established that the SHIPPED short codes cannot be substrings of one
// another (`{{`/`}}` delimiters make `{{CARD}}` ⊄ `{{IDCARD}}`), so the live
// risk surface is operator-authored labels via `mask_labels`, which may be any
// string. The detector's planner.ValidateLabels rejects colliding tables at
// load time; this scan is the proxy-side half of that defense, because the
// proxy must stay correct against ANY child it is handed (older build, skewed
// protocol version) rather than trusting the child's validation.
//
// Longest-match-wins is what makes the two halves agree: whatever the detector
// actually substituted is the longest token that fits at that position, since a
// shorter token could only match there by living inside the longer one.
func scanTokenOccurrences(s string, tokens []string) map[string][]int {
	if len(tokens) == 0 || s == "" {
		return nil
	}
	// Order longest-first so the first match at a position is the longest one.
	ordered := make([]string, len(tokens))
	copy(ordered, tokens)
	sort.SliceStable(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	// First-byte filter: shipped tokens all start with '{', so ordinary prose
	// skips the inner loop entirely.
	var firstBytes [256]bool
	for _, t := range ordered {
		firstBytes[t[0]] = true
	}
	out := make(map[string][]int, len(tokens))
	for i := 0; i < len(s); {
		if !firstBytes[s[i]] {
			i++
			continue
		}
		matched := ""
		for _, t := range ordered {
			if strings.HasPrefix(s[i:], t) {
				matched = t
				break
			}
		}
		if matched == "" {
			i++
			continue
		}
		out[matched] = append(out[matched], i)
		i += len(matched)
	}
	return out
}

// renumberRestorables rewrites each restorable token occurrence in masked into
// a per-request numbered label and records label→original (sliced from head —
// the exact bytes the detector's spans refer to) into st.
//
// Validation is all-or-nothing PER RESTORABLE and fails toward the safe side:
// on any inconsistency (bad spans, token/span count mismatch) that restorable
// keeps its numberless token — the sensitive text stays masked, only the
// response-side restore is lost. WARN carries counts only, never content.
//
// It also returns spanLabels: the [start,end) span of each masked original in
// HEAD → the label that span went upstream as. This is the ONLY output of the
// numbering; nothing else in the proxy or the detector may derive a label. The
// caller equal-joins it onto the compliance event's per-finding offsets, which
// live in the same coordinate system (both the event's start/end_offset and the
// detector's MaskMeta spans are raw-frame offsets into the very payload this
// function receives as `head`). See injectWireLabels for why the join is per
// PIECE and never across pieces.
//
// 🔴 The map is deliberately keyed on the span and NOT on the label: a label is
// unique per request, but this map is consumed per piece, and building the
// reverse direction would invite a "look up a finding by its label" call site —
// exactly the ambiguity the three degrade paths below exist to avoid. A span
// with no entry means "this text was not substituted by a placeholder of its
// own", which is a meaningful answer, not a lookup failure.
//
// Privacy: keys are integer offsets and values are synthetic placeholder names.
// No original text is in the returned map (the label→original table stays in
// st, per-request memory only, never persisted/uploaded/logged).
func renumberRestorables(head, masked string, restorables []apphook.RestorableMask, st *maskRestore, logger *slog.Logger) (string, map[[2]int]string) {
	usable, tokens := usableRestorables(restorables, logger)
	if len(usable) == 0 {
		// Degrade path 3 (two families share one token) lands here when it drops
		// everything: no labels are allocated, so no span gets one. The caller
		// backfills nothing and the finding records "not placeholder-substituted",
		// which is exactly what happened.
		return masked, nil
	}
	positionsByToken := scanTokenOccurrences(masked, tokens)

	type occ struct {
		pos      int
		tokenLen int
		prefix   string
		suffix   string
		orig     string
		span     [2]int
	}
	var occs []occ
	for _, r := range usable {
		valid := true
		prevEnd := 0
		for _, sp := range r.Spans {
			if sp[0] < prevEnd || sp[0] >= sp[1] || sp[1] > len(head) {
				valid = false
				break
			}
			prevEnd = sp[1]
		}
		positions := positionsByToken[r.Token]
		if !valid || len(positions) != len(r.Spans) {
			// Count mismatch: e.g. the user's own text contains the literal token,
			// or spans drifted. Alignment is ambiguous → keep the numberless mask.
			logger.Warn("filter: restorable mask alignment mismatch; keeping numberless mask, restore skipped",
				"event.name", observability.EventProxyFilterRestoreAlignMismatch,
				"token_occurrences", len(positions), "spans", len(r.Spans), "spans_valid", valid)
			continue
		}
		for i, pos := range positions {
			// prefix/suffix come from THIS restorable, not from a scan keyed on the
			// token (the pre-P2 shape): with several families in one request a
			// linear "first restorable whose Token matches" lookup hands family B
			// family A's numbered form (串味).
			occs = append(occs, occ{
				pos: pos, tokenLen: len(r.Token),
				prefix: r.NumberedPrefix, suffix: r.NumberedSuffix,
				orig: head[r.Spans[i][0]:r.Spans[i][1]],
				span: r.Spans[i],
			})
		}
	}
	if len(occs) == 0 {
		// Degrade path 1 (token occurrences ≠ span count) dropped every family.
		return masked, nil
	}
	// Numbered in text order — the numbers the user's forwarded prompt shows must
	// run 1,2,3… left to right regardless of which family each one belongs to.
	sort.SliceStable(occs, func(i, j int) bool { return occs[i].pos < occs[j].pos })
	// Guard: merged occurrences must not overlap. scanTokenOccurrences already
	// guarantees this (one pass, cursor advanced past each match); kept as the
	// cheap invariant assertion for the day someone changes the scanner.
	for i := 1; i < len(occs); i++ {
		if occs[i].pos < occs[i-1].pos+occs[i-1].tokenLen {
			logger.Warn("filter: restorable mask occurrences overlap; keeping numberless mask, restore skipped",
				"event.name", observability.EventProxyFilterRestoreAlignMismatch,
				"token_occurrences", len(occs), "spans", -1, "spans_valid", false)
			// Degrade path 2 (merged occurrences overlap): the whole piece keeps the
			// numberless mask, so no span has a label to report.
			return masked, nil
		}
	}
	// Rebuild left→right, allocating request-scoped numbers.
	//
	// 🔴 This is the ONE place in the entire system that composes a numbered
	// label. Everything downstream — the response-leg restore table, the health
	// counters, and the wire_label recorded on the compliance event — reads the
	// labels produced HERE. Do not add a second composer anywhere (fenced by
	// TestFilterRestore_SingleNumberingSource).
	var sb strings.Builder
	sb.Grow(len(masked) + len(occs)*4)
	spanLabels := make(map[[2]int]string, len(occs))
	last := 0
	for _, o := range occs {
		label := o.prefix + strconv.Itoa(st.nextN) + o.suffix
		st.nextN++
		sb.WriteString(masked[last:o.pos])
		sb.WriteString(label)
		st.add(label, o.orig)
		spanLabels[o.span] = label
		last = o.pos + o.tokenLen
	}
	sb.WriteString(masked[last:])
	return sb.String(), spanLabels
}

// usableRestorables filters the child's metadata down to the families the
// renumberer may act on, and returns their tokens for the occurrence scan.
//
// It enforces the P1 wire invariant "one token ⇒ exactly one Restorable"
// (alias entities such as CN_PHONE/PHONE share a placeholder, so the detector
// MERGES their spans into a single Restorable before sending). If that ever
// breaks — an older child, a protocol skew, a regression in the grouping — the
// consequence downstream is silent and severe: scanTokenOccurrences reports the
// SAME occurrence list to both entries, so every occurrence is consumed twice
// and the second family's numbers are written over the first family's spans,
// handing the user someone else's original text on the response leg.
//
// 处置 = drop EVERY family sharing the duplicated token, keep the numberless
// mask, WARN. WHY not fail the request (fail-loud in the hard sense): the
// sensitive text is ALREADY masked at this point, so dropping restore costs the
// user a placeholder they must read past — while failing the request would
// break traffic over a detector-metadata defect, violating the fail-open
// invariant (方案 §5.7 / §6 #11) that governs the whole filter chain. WHY not
// keep the first and drop the rest: with two span lists and one occurrence
// list, "which spans belong to which occurrences" is exactly the ambiguity that
// makes the result wrong; there is no safe pick. The WARN is the loud part —
// it names a wire-contract violation, not a content anomaly, so it carries
// counts only.
func usableRestorables(restorables []apphook.RestorableMask, logger *slog.Logger) (usable []apphook.RestorableMask, tokens []string) {
	seen := make(map[string]int, len(restorables))
	for _, r := range restorables {
		if !restorableWellFormed(r) {
			continue
		}
		seen[r.Token]++
	}
	usable = make([]apphook.RestorableMask, 0, len(restorables))
	tokens = make([]string, 0, len(restorables))
	dropped := 0
	for _, r := range restorables {
		if !restorableWellFormed(r) {
			continue
		}
		if seen[r.Token] > 1 {
			dropped++
			continue
		}
		usable = append(usable, r)
		tokens = append(tokens, r.Token)
	}
	if dropped > 0 {
		logger.Warn("filter: detector sent several restorables for one placeholder token; restore skipped for them (wire contract: one token ⇒ one restorable)",
			"event.name", observability.EventProxyFilterRestoreDuplicateToken,
			"restorables", len(restorables), "dropped", dropped, "usable", len(usable))
	}
	return usable, tokens
}

func restorableWellFormed(r apphook.RestorableMask) bool {
	return r.Token != "" && (r.NumberedPrefix != "" || r.NumberedSuffix != "") && len(r.Spans) > 0
}

// restoreMaskedResponseBody swaps numbered placeholders back to their original
// text in a NON-STREAMING response body (B3 响应侧还原, spec 规则 2 唯一例外).
//
// Strategy: decode the whole JSON tree (json.Number preserves numeric
// fidelity), replace inside every string value — placeholder text can only
// live inside JSON strings, and decoding sidesteps \uXXXX-escaping mismatches
// a raw byte replace would suffer — then re-encode. Runs ONLY when this
// request built a restore mapping (nil check in the caller); any failure
// returns the body unchanged (fail-open: the client sees placeholders, which
// is degraded but safe — never a corrupted body).
func restoreMaskedResponseBody(ctx context.Context, body []byte, logger *slog.Logger) []byte {
	st := maskRestoreFromContext(ctx)
	if st == nil || len(body) == 0 {
		return body
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		logger.Warn("filter: response body not JSON; placeholder restore skipped",
			"event.name", "proxy.filter.restore_body_not_json",
			"error", err, "body_bytes", len(body))
		return body
	}
	replaced, changed := restoreJSONStrings(root, st)
	if !changed {
		return body // no placeholder present — forward upstream bytes verbatim
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(replaced); err != nil {
		logger.Warn("filter: restored body re-encode failed; forwarding upstream body",
			"event.name", "proxy.filter.restore_encode_failed", "error", err)
		return body
	}
	return bytes.TrimRight(out.Bytes(), "\n") // Encoder appends a newline
}

// reasoningBlockTypes lists the JSON `type` values of response blocks that carry
// the model's INTERNAL reasoning instead of its answer. Restore skips such a
// block WHOLE — see the leak chain below (S3, 用户拍板 2026-08-09).
//
// 🔴 WHY (the residual leak this cuts, bugfix 20260809-thinking-block-restore-leak):
// the request leg deliberately does NOT scan `thinking` / `redacted_thinking`,
// because those blocks carry a `signature` the Anthropic API verifies when the
// client replays them — rewriting their text makes the upstream reject the
// request outright (HTTP 400). Restore, however, was a whole-tree string
// replace, so a placeholder the model echoed INSIDE its thinking was handed back
// to the client as the ORIGINAL text; the client stores that in its history and
// replays it next turn inside a thinking block — the one place the scanner may
// not touch. From turn 2 on the sensitive original reached the upstream LLM in
// plaintext, HTTP 200 all the way, with no signal anywhere.
//
// Keeping the placeholder inside reasoning blocks cuts the chain at ZERO
// technical risk (nothing signed is rewritten) and is also the self-consistent
// choice: what the client replays then matches byte-for-byte what the model
// actually reasoned over last turn, rather than a doctored reasoning record.
// The whole cost is cosmetic — a user who expands "thinking" sees `{{ADDR_1}}`.
//
// Members (structural `type` values, never a text heuristic):
//   - thinking / redacted_thinking — Anthropic extended-thinking blocks.
//   - reasoning — OpenAI Responses API reasoning items. Same echo-back shape:
//     the item's `summary[].text` is plaintext and clients replay the item
//     (with its `encrypted_content`) on the next turn for context preservation,
//     while the inbound scanner only collects text / input_text / output_text
//     parts (filter_content.go collectContentField) — so the identical chain
//     exists on the Responses wire.
var reasoningBlockTypes = map[string]bool{
	"thinking":          true,
	"redacted_thinking": true,
	"reasoning":         true,
}

// restoreSkipBlockTypes is the set of block `type` values restore walks PAST
// whole. It is DERIVED, not hand-written, from one rule:
//
//	🔴 Never write an original into a channel the request leg cannot MASK.
//
// The spec (2026-06-04 关键不变量) states this as "新增任何还原通道前，必须先确认
// 该通道在请求侧可扫". "可扫" was the right test while scanning and masking were
// the same thing. Since 2026-08-10 (方案②) they are not: agent tool blocks ARE
// scanned, but at ceilingAudit — findings are recorded and the bytes are
// forwarded untouched. So a placeholder the model echoes inside a `tool_use`
// argument, restored to plaintext, would come back next turn in a block that
// gets an audit event and no mask — i.e. the S3 thinking chain again, one rung
// louder but just as leaky. The operative test is therefore "可 mask", and both
// exclusion families fall out of it automatically:
//
//   - reasoning blocks — not in blockScanPolicy at all → not scannable → not
//     maskable (their `signature` is verified upstream; see the note above);
//   - tool_result / tool_use — in the policy, but ceiling < ceilingFull.
//
// Because the set is derived from blockScanPolicy, the two legs cannot drift:
// raising a row to ceilingFull re-opens restore for it in the same edit, and
// opening a new audit-only block type closes restore for it in the same edit.
// Fenced by TestRestoreSkip_DerivedFromBlockScanPolicy.
//
// Built lazily (sync.OnceValue) because blockScanPolicy is populated in init()
// — see the note there — and package-var initializers run before init().
var restoreSkipBlockTypes = sync.OnceValue(func() map[string]bool {
	return buildRestoreSkipBlockTypes(reasoningBlockTypes, blockScanPolicy)
})

func buildRestoreSkipBlockTypes(reasoning map[string]bool, policy map[string]blockScanRule) map[string]bool {
	skip := make(map[string]bool, len(reasoning)+len(policy))
	for t, on := range reasoning {
		if on {
			skip[t] = true
		}
	}
	for t, rule := range policy {
		if rule.ceiling != ceilingFull {
			skip[t] = true
		}
	}
	return skip
}

// reasoningTextFields lists reasoning channels that are a SIBLING FIELD of the
// answer rather than a typed block, so reasoningBlockTypes cannot catch them:
// OpenAI-compatible chat-completions bodies put the chain of thought in
// `choices[].message.reasoning_content` next to `content` (DeepSeek-R1 shape,
// adopted by Kimi and others). Excluded for the same reason and, additionally,
// for leg parity: the streaming path never restored it either (sseTextFieldPath
// only recognizes `choices.0.delta.content`), so restoring it non-streaming made
// the same response differ between stream: true and stream: false.
var reasoningTextFields = map[string]bool{
	"reasoning_content": true,
}

// restoreJSONStrings walks a decoded JSON tree replacing placeholders inside
// string values. Returns the (possibly shared) tree and whether anything changed.
func restoreJSONStrings(v any, st *maskRestore) (any, bool) {
	switch t := v.(type) {
	case string:
		if r := st.restore(t); r != t {
			return r, true
		}
		return t, false
	case map[string]any:
		// S3 + 方案②: blocks the request leg cannot MASK are skipped WHOLE, and the
		// decision is made on the block's JSON `type` — structure, never "does this
		// text look like a thinking block", which would both miss and over-match.
		// The set is derived from blockScanPolicy; see restoreSkipBlockTypes.
		//
		// Deny-list, deliberately not an allow-list: this walker also traverses
		// nodes that are not content blocks at all — including the response ROOT,
		// which carries `"type":"message"`. An allow-list keyed on `type` would
		// skip the entire body.
		if ty, _ := t["type"].(string); restoreSkipBlockTypes()[ty] {
			return t, false
		}
		changed := false
		for k, val := range t {
			if reasoningTextFields[k] {
				continue
			}
			nv, c := restoreJSONStrings(val, st)
			if c {
				t[k] = nv
				changed = true
			}
		}
		return t, changed
	case []any:
		changed := false
		for i, val := range t {
			nv, c := restoreJSONStrings(val, st)
			if c {
				t[i] = nv
				changed = true
			}
		}
		return t, changed
	default:
		return v, false
	}
}
