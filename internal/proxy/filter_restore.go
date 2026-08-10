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
	canonicalLabelRe = regexp.MustCompile(`^\{\{([A-Za-z][A-Za-z0-9]*)_([0-9]{1,9})\}\}$`)

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
		`^\{\{?[ \t]?["'` + "`" + `\x{201C}\x{2018}]?[ \t]?(?:[A-Za-z][A-Za-z0-9]*)?(?:[ \t]?_[ \t]?[0-9]{0,9}[ \t]?(?:["'` + "`" + `\x{201D}\x{2019}]?)[ \t]?\}?)?$`)
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
	open := strings.LastIndexByte(tail, '{')
	if open < 0 {
		return ""
	}
	cand := tail[open:]
	if !tolerantPlaceholderPrefixRe.MatchString(cand) {
		return ""
	}
	return cand
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
func renumberRestorables(head, masked string, restorables []apphook.RestorableMask, st *maskRestore, logger *slog.Logger) string {
	type occ struct {
		pos   int
		token string
		orig  string
	}
	var occs []occ
	tokens := make([]string, 0, len(restorables))
	for _, r := range restorables {
		if r.Token != "" {
			tokens = append(tokens, r.Token)
		}
	}
	positionsByToken := scanTokenOccurrences(masked, tokens)
	for _, r := range restorables {
		if r.Token == "" || (r.NumberedPrefix == "" && r.NumberedSuffix == "") || len(r.Spans) == 0 {
			continue
		}
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
				"event.name", "proxy.filter.restore_align_mismatch",
				"token_occurrences", len(positions), "spans", len(r.Spans), "spans_valid", valid)
			continue
		}
		for i, pos := range positions {
			occs = append(occs, occ{pos: pos, token: r.Token, orig: head[r.Spans[i][0]:r.Spans[i][1]]})
		}
	}
	if len(occs) == 0 {
		return masked
	}
	// Numbered in text order. Each restorable contributes its own position list,
	// so sort the merged list before allocating request-scoped numbers.
	for i := 1; i < len(occs); i++ {
		for j := i; j > 0 && occs[j-1].pos > occs[j].pos; j-- {
			occs[j-1], occs[j] = occs[j], occs[j-1]
		}
	}
	// Guard: merged occurrences must not overlap (impossible with one
	// restorable; defensive for future multi-token metadata).
	for i := 1; i < len(occs); i++ {
		if occs[i].pos < occs[i-1].pos+len(occs[i-1].token) {
			logger.Warn("filter: restorable mask occurrences overlap; keeping numberless mask, restore skipped",
				"event.name", "proxy.filter.restore_align_mismatch",
				"token_occurrences", len(occs), "spans", -1, "spans_valid", false)
			return masked
		}
	}
	// Rebuild left→right, allocating request-scoped numbers.
	prefixSuffix := func(token string) (string, string) {
		for _, r := range restorables {
			if r.Token == token {
				return r.NumberedPrefix, r.NumberedSuffix
			}
		}
		return "", ""
	}
	var sb strings.Builder
	sb.Grow(len(masked) + len(occs)*4)
	last := 0
	for _, o := range occs {
		pre, suf := prefixSuffix(o.token)
		label := pre + strconv.Itoa(st.nextN) + suf
		st.nextN++
		sb.WriteString(masked[last:o.pos])
		sb.WriteString(label)
		st.add(label, o.orig)
		last = o.pos + len(o.token)
	}
	sb.WriteString(masked[last:])
	return sb.String()
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
		changed := false
		for k, val := range t {
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
