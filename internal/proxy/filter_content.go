// filter_content.go — L1 envelope content extraction for the filter dispatcher.
//
// The filter hook (ai-compliance-detector / DLP / …) must only ever see prompt
// CONTENT, never the JSON wire envelope (`{"model":…,"messages":[{"content":…}]}`).
// Otherwise masking text spans in the raw body can slice JSON delimiters and
// break the request structure — which is exactly what real Anthropic rejected
// with 400 "not valid JSON" before L1.
//
// Per the architecture (§line233 "ComplianceHook 截获 prompt → stdin pipe") the
// proxy owns the wire envelope (it already parses it for model/usage/translation)
// and hands the hook only the prompt text. This file extracts those content
// strings and provides setters to write the masked text back, so re-serializing
// preserves the envelope + escaping (handled by encoding/json).
//
// Scope (L1): inbound request bodies for the Anthropic /v1/messages and OpenAI
// /v1/chat/completions shapes — `messages[].content` (string or array of
// {type:"text", text:…} blocks) and top-level `system` (string or block array).
// Out of scope: outbound/streaming responses (DC4 "一阶段不做流式替换"), and
// structure preservation WITHIN a content value when the content itself is
// JSON/Markdown (that is H9 / L2, the child's Replacement Planner).
package proxy

import (
	"encoding/json"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// ─────────────────────────────────────────────────────────────────────────────
// Scan-role policy (P4, 方案 §3.4 "扫描范围扩展：assistant 消息纳入")
// ─────────────────────────────────────────────────────────────────────────────
//
// WHY this is configuration and not a hard-coded skip list: which roles carry
// user-originated content is a POLICY question that changed twice already —
//   - 2026-06-16 (history leak): "only the latest user turn" → "every user turn";
//   - 2026-08-08 (placeholder restore): "user only" → "user + assistant", because
//     response-side restoration hands the CLIENT the plaintext back, so from the
//     second turn on the same plaintext returns inside an ASSISTANT message. A
//     skip list that excludes assistant makes masking a first-turn-only feature
//     (方案 §2.2). Future protocol shapes (tool / function results) are the next
//     candidate, so the axis gets a name and a knob instead of a third edit here.
//
// FAIL-SAFE (never silently under-scan): the policy is an allow-list over a
// CLOSED universe of roles we can reason about. Anything OUTSIDE that universe —
// an empty/missing role, or a role a future client invents — is ALWAYS scanned.
// So a wire format we have never seen degrades toward over-scanning (a masked
// benign string), never toward leaking. This preserves the pre-P4 behavior of
// the deny-list exactly: with roles={user}, unknown roles were scanned too.

// knownMessageRoles is the closed universe of chat roles the proxy recognizes,
// across Anthropic + OpenAI-family (chat/Responses, Codex/Kimi) + OpenClaw.
// A role in this set is scanned only if the policy lists it; a role NOT in this
// set is always scanned (see scanRoleSet.scans).
var knownMessageRoles = map[string]struct{}{
	"user":      {},
	"assistant": {},
	"system":    {},
	"developer": {}, // OpenAI's system-equivalent
	"tool":      {},
	"function":  {}, // OpenAI legacy tool output
}

// scanRoleSet is the configured set of roles the inbound compliance filter
// scans. The zero value (nil) means "use defaultScanRoles" so a Proxy built
// without explicit configuration behaves like a configured one.
type scanRoleSet map[string]struct{}

// defaultScanRoles — user + assistant (方案 §3.4).
//
//   - user: the human's own input, every turn (2026-06-16 history-leak fix).
//   - assistant: model replies REPLAYED as history. They are not "the model's
//     live response" (the inbound filter still never governs the response leg);
//     they are text the client is sending upstream now, and after placeholder
//     restoration that text is the user's plaintext.
//
// system/developer are deliberately absent: masking admin-authored instructions
// corrupts the agent's directives. tool/function are absent pending a decision
// on tool output (the knob makes that a config change, not a code change).
var defaultScanRoles = scanRoleSet{"user": {}, "assistant": {}}

// scans reports whether a message with this role must be handed to the detector.
// nil receiver → the default policy.
func (s scanRoleSet) scans(role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	if _, known := knownMessageRoles[r]; !known {
		return true // empty / unrecognized role → fail-safe scan
	}
	if s == nil {
		s = defaultScanRoles
	}
	_, ok := s[r]
	return ok
}

// list returns the configured roles sorted, for logging/diagnostics.
func (s scanRoleSet) list() []string {
	if s == nil {
		s = defaultScanRoles
	}
	out := make([]string, 0, len(s))
	for r := range s {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// newScanRoleSet builds a policy from raw configured role names. Names are
// normalised (trim + lowercase) and validated against knownMessageRoles.
//
// Returns rejected names so the caller can WARN instead of silently dropping
// them (日志规范: no silent fallback to a default). If NOTHING valid remains the
// result is nil = default policy — an operator typo must not disable scanning.
func newScanRoleSet(raw []string) (set scanRoleSet, rejected []string) {
	set = scanRoleSet{}
	for _, r := range raw {
		n := strings.ToLower(strings.TrimSpace(r))
		if n == "" {
			continue
		}
		if _, known := knownMessageRoles[n]; !known {
			rejected = append(rejected, r)
			continue
		}
		set[n] = struct{}{}
	}
	if len(set) == 0 {
		return nil, rejected // nil → default (fail-safe, never "scan nothing")
	}
	return set, rejected
}

// ─────────────────────────────────────────────────────────────────────────────
// Block-type scan policy + action ceiling (2026-08-10 拍板 方案②)
// ─────────────────────────────────────────────────────────────────────────────
//
// WHAT this solves: an agent client's biggest payload is not the human's
// sentence, it is TOOL traffic — `tool_result` (the file/command output the
// client feeds back) and `tool_use.input` (the arguments, e.g. a shell command
// line). Both used to be dropped by the block-type switch below, so customer
// source, config and credentials crossed to the LLM with no scan, no WARN and
// no audit event (实证 aikey-test/auditeye/tool_result_scope_test.go arms B/C).
//
// WHY the scan is opened but the ACTION is capped (方案②, not 方案①): the
// built-in credential ruleset is gitleaks-derived — 222 rules of which 216 are
// `block`. Pointing those at every file an agent reads would turn a benign test
// fixture into a hard `COMPLIANCE_BLOCKED` on the user's main path, and no one
// has ever measured that hit rate on CODE corpora (the `mask-FP=0` holdout is
// CONVERSATION corpora). So step one is: see everything, change nothing —
// record findings, forward the bytes untouched. That produces the code-corpus
// data 方案① needs, and its failure direction is "we logged it", never "we
// broke the user's turn".
//
// 🔴 WHY the two live in ONE table: "widen the block types" and "cap the
// action" must be physically impossible to do separately. If someone widens the
// switch and forgets the cap, 方案① ships by accident — 216 block rules onto the
// agent hot path. Here a block type is scannable ONLY by having a row in
// blockScanPolicy, and every row carries its ceiling; nesting takes the MINIMUM
// of the inherited and the row ceiling, so text nested inside a tool block can
// never come back out at full ceiling. Fences: TestBlockScanPolicy_* in
// filter_toolblock_test.go.

// actionCeiling caps the strongest verdict the dispatcher may APPLY to a
// content piece, regardless of what the detector returned for it.
//
// 🔴 The zero value is ceilingAudit — the WEAKEST rung — on purpose. Opening a
// block type means writing a struct literal into blockScanPolicy; if the author
// omits the ceiling field, Go hands them "audit" and the new block type can only
// ever produce events. The opposite slip (omitting ceilingFull on an ordinary
// text block) merely turns masking off for it and is caught loudly by the whole
// existing mask suite. So the field that is easy to forget fails toward "we
// recorded it", never toward "we refused the user's request".
type actionCeiling uint8

const (
	// ceilingAudit — record the compliance event, forward the content BYTE
	// UNCHANGED. mask → allow (no rewrite), block → allow (request proceeds).
	// warn is left as warn: it already passes through untouched, so capping it
	// further would only lose signal.
	ceilingAudit actionCeiling = iota
	// ceilingFull — apply whatever the detector decided (mask / block / warn).
	ceilingFull
	// ceilingOff — the row does not apply at all: the block type is NOT
	// extracted, nothing is sent to the detector, no event is produced. This is
	// the operator OFF rung (see toolBlockScanMode), not an enforcement outcome.
	//
	// 🔴 It is placed AFTER ceilingFull in the iota order on purpose, so the zero
	// value stays ceilingAudit. A row (or a contentPiece) whose author forgot the
	// field must land on "we recorded it", never on "we silently scanned
	// nothing" — a silent under-scan is the leak direction this whole file
	// exists to fight. Ordering is expressed by rank() instead of the raw
	// integer, precisely so the two concerns stay independent.
	ceilingOff
)

// rank orders the rungs by how much they PERMIT: off(0) < audit(1) < full(2).
//
// Deliberately not the iota order — see the ceilingOff comment. An unrecognized
// value ranks as audit, so a corrupted/未来 rung degrades toward "record it",
// never toward "do whatever the detector said" nor toward "scan nothing".
func (c actionCeiling) rank() uint8 {
	switch c {
	case ceilingOff:
		return 0
	case ceilingAudit:
		return 1
	case ceilingFull:
		return 2
	default: // any unknown value degrades to the audit rung
		return 1
	}
}

// tighten returns the stricter of two ceilings. Nesting (a text block inside a
// tool_result) can therefore only ever LOWER the ceiling, never raise it — and
// with the OFF rung ranked lowest, a disabled parent disables everything nested
// under it too.
func (c actionCeiling) tighten(other actionCeiling) actionCeiling {
	if other.rank() < c.rank() {
		return other
	}
	return c
}

// clamp applies the ceiling to a detector verdict. capped reports whether the
// verdict was actually downgraded — the caller uses it to keep the audit record
// honest (the event must not claim "masked" when nothing was masked) and to
// surface the downgrade in logs.
func (c actionCeiling) clamp(a apphook.Action) (effective apphook.Action, capped bool) {
	if c == ceilingFull {
		return a, false
	}
	switch a {
	case apphook.ActionMask, apphook.ActionBlock:
		return apphook.ActionAllow, true
	case apphook.ActionAllow, apphook.ActionWarn:
		return a, false
	}
	return a, false
}

// String renders the ceiling for logs / audit records. Deliberately uses the
// detector's own ladder vocabulary (off|audit|warn|mask) so an operator reading
// `action_taken` on a capped event sees a value from the same dictionary.
func (c actionCeiling) String() string {
	switch c {
	case ceilingFull:
		return "full"
	case ceilingOff:
		return "off"
	case ceilingAudit:
		return "audit"
	default:
		return "audit"
	}
}

// blockScanRule is one row of the block-type scan policy: HOW to pull text out
// of that block shape, and the ceiling every piece it yields is stamped with.
type blockScanRule struct {
	extract func(block map[string]any, ceiling actionCeiling, depth int, out *[]contentPiece)
	ceiling actionCeiling
}

// blockScanPolicy is the ONE place a content block type becomes scannable.
// A type absent from this table is not extracted at all (image / document /
// base64 attachments, and Anthropic `thinking` — the latter deliberately, see
// the DELIBERATE EXCLUSIONS note on collectContentField).
//
// Populated in init() rather than as a var literal for ONE mechanical reason:
// extractToolResultBlock recurses back through the walker that reads this table
// (that is the point — no second copy of the block switch), and Go rejects the
// resulting package-var initialization cycle. Semantics are unchanged: this is
// still the single table, and nothing outside it can widen the scan.
// (type alias, not a defined type, so it stays assignable to the plain map that
// buildRestoreSkipBlockTypes and the existing fences already take.)
type blockScanTable = map[string]blockScanRule

// blockScanPolicy is the CANONICAL table: every scannable block type at the
// strongest rung it is allowed to run at. It never changes at runtime.
//
// 🔴 Read this one — not the effective table — when the question is "what COULD
// this block type do". filter_restore.go derives restoreSkipBlockTypes from it
// for exactly that reason: restore must stay closed for tool blocks even when an
// operator has turned tool SCANNING off, otherwise switching the scan off would
// silently re-open a plaintext echo channel (the S3 chain). The toggle governs
// what is scanned, never what may be restored.
var blockScanPolicy blockScanTable

// activeBlockScanPolicyPtr is the EFFECTIVE table the walker consults — the
// canonical one with the toggle-governed rows moved to their configured rung.
//
// Swapped atomically and never mutated in place: the tables are immutable after
// construction, so the hot path reads them from many goroutines with no lock.
// Process-global rather than per-Proxy because the extractor is a package-level
// pure function chain (collectContentField → rule.extract → collectContentField
// recursion) and there is exactly one filter policy per proxy process; threading
// a policy argument through that recursion would mean changing blockScanRule's
// function type, i.e. refactoring the very table this switch must not disturb.
var activeBlockScanPolicyPtr atomic.Pointer[blockScanTable]

func init() {
	blockScanPolicy = buildBlockScanPolicy(toolBlockCeilingFor(defaultToolBlockScanMode))
	SetToolBlockScanMode(string(defaultToolBlockScanMode))
}

// buildBlockScanPolicy is the ONE literal of the table. toolCeiling is the rung
// the agent-tool rows run at — passing it in is what makes the switch and the
// action cap physically inseparable: you cannot turn the rows on without naming
// the ceiling they run at.
//
// Kept a function (rather than a package-var literal) for the same mechanical
// reason it used to be built in init(): extractToolResultBlock recurses back
// through the walker that reads this table, and Go rejects the resulting
// package-var initialization cycle.
func buildBlockScanPolicy(toolCeiling actionCeiling) blockScanTable {
	return blockScanTable{
		// Ordinary prose. "text" = Anthropic/OpenAI chat content block;
		// "input_text" = OpenAI Responses API user content part (codex);
		// "output_text" = the Responses API ASSISTANT content part, i.e. how a
		// replayed model reply carries its text in input[] (added by P4 2026-08-08:
		// without it an assistant turn matched the role filter and then yielded ZERO
		// pieces, leaving the restore leak open for codex/Responses clients).
		//
		// NOT governed by the toggle: prose is the main masking path.
		"text":        {extract: extractFlatTextBlock, ceiling: ceilingFull},
		"input_text":  {extract: extractFlatTextBlock, ceiling: ceilingFull},
		"output_text": {extract: extractFlatTextBlock, ceiling: ceilingFull},

		// Agent tool traffic — scanned for AUDIT ONLY (方案②, see the header note).
		// Do NOT raise these to ceilingFull without the code-corpus holdout and the
		// sealed re-run that `mask-FP=0` requires; the fences will go red if you do.
		// toolCeiling is either that audit rung or ceilingOff (toggle off).
		"tool_result": {extract: extractToolResultBlock, ceiling: toolCeiling},
		"tool_use":    {extract: extractToolUseBlock, ceiling: toolCeiling},
	}
}

// effectiveBlockScanPolicy returns the table the walker must use right now.
func effectiveBlockScanPolicy() blockScanTable {
	if p := activeBlockScanPolicyPtr.Load(); p != nil {
		return *p
	}
	return blockScanPolicy // unreachable after init(); fail toward "scan more"
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool-block scan switch (operator rung)
// ─────────────────────────────────────────────────────────────────────────────
//
// WHY a switch at all: opening tool traffic (方案② 2026-08-10) buys audit
// coverage of the biggest part of an agent payload, but it costs one extra
// detector round-trip per tool block on the request hot path. On a cold, slow
// box that is a latency the operator may not be able to accept, and the honest
// answer must be "turn it off", not "suffer or disable compliance entirely".
//
// WHY it is a RUNG on the existing ceiling and not a bool: the same paradigm the
// CN_ADDRESS lane switch uses (ai-compliance-detector actionpolicy
// entity_actions.CN_ADDRESS = off|audit|warn|mask, 拍板 2026-08-08) — the level
// and the on/off state are ONE ladder with ONE source of truth. Here the
// ladder value IS the row's `ceiling` field, so the hard constraint from 方案②
// survives the switch: "widen the block types" and "cap the action" are still
// the same edit. `off` means the row does not apply at all (nothing extracted,
// nothing sent to the detector), NOT "scan but don't cap".
//
// WHY the default is ON (audit): it keeps the behavior that was already
// reviewed and accepted on 2026-08-10, and its failure direction is "we logged
// something we did not need to". Defaulting to off would silently return the
// blind spot that aikey-test/auditeye/tool_result_scope_test.go arms B/C proved.
// Absent / unrecognized config degrades to this default, NEVER to off — same
// asymmetry as AddressLaneAction().
type toolBlockScanMode string

const (
	// toolBlockScanOff — do not extract tool_result / tool_use at all. Byte-for-
	// byte the pre-2026-08-10 behavior on the request leg.
	toolBlockScanOff toolBlockScanMode = "off"
	// toolBlockScanAudit — extract them, cap every verdict at audit.
	toolBlockScanAudit toolBlockScanMode = "audit"
)

// defaultToolBlockScanMode — see "WHY the default is ON" above.
const defaultToolBlockScanMode = toolBlockScanAudit

// toolBlockCeilingFor is the ONE place a rung is paired with the ceiling its
// rows run at. A future rung (e.g. "mask", once the code-corpus holdout exists)
// cannot be added without stating its ceiling right here.
//
// An unrecognized rung returns the DEFAULT rung's ceiling — validation lives in
// SetToolBlockScanMode, which reports the rejection so the caller can WARN
// (日志规范: no silent fallback).
func toolBlockCeilingFor(m toolBlockScanMode) actionCeiling {
	switch m {
	case toolBlockScanOff:
		return ceilingOff
	case toolBlockScanAudit:
		return ceilingAudit
	default:
		return ceilingAudit
	}
}

// SetToolBlockScanMode applies an operator rung for agent tool traffic. Called
// once at startup by the supervisor from AIKEY_PROXY_FILTER_TOOL_BLOCKS.
//
// Returns the rung actually in effect and ok=false when the input was not
// recognized (the caller WARNs; an operator typo must not silently change what
// is scanned, in either direction).
func SetToolBlockScanMode(raw string) (applied string, ok bool) {
	m := toolBlockScanMode(strings.ToLower(strings.TrimSpace(raw)))
	switch m {
	case toolBlockScanOff, toolBlockScanAudit:
		ok = true
	case "":
		m, ok = defaultToolBlockScanMode, true // unset → default, not an error
	default:
		m, ok = defaultToolBlockScanMode, false
	}
	table := buildBlockScanPolicy(toolBlockCeilingFor(m))
	activeBlockScanPolicyPtr.Store(&table)
	return string(m), ok
}

// ToolBlockScanMode reports the rung currently in effect, for the health
// surface and diagnostics. Derived from the live table — never from a shadow
// copy of the setting — so what is reported is what is actually running.
func ToolBlockScanMode() string {
	if effectiveBlockScanPolicy()["tool_result"].ceiling == ceilingOff {
		return string(toolBlockScanOff)
	}
	return string(toolBlockScanAudit)
}

// blockNestDepthCap bounds the walk through nested block payloads
// (tool_result.content arrays, tool_use.input objects). Real wire shapes nest
// 1-3 deep; the cap exists so a hostile or malformed body cannot turn extraction
// into an unbounded recursion on the hot path.
const blockNestDepthCap = 8

// extractFlatTextBlock handles the shapes whose payload is a flat `text` string.
func extractFlatTextBlock(block map[string]any, ceiling actionCeiling, _ int, out *[]contentPiece) {
	txt, isStr := block["text"].(string)
	if !isStr || txt == "" {
		return
	}
	b := block // capture this block for the setter closure
	*out = append(*out, contentPiece{
		text:    txt,
		ceiling: ceiling,
		setText: func(s string) { b["text"] = s },
	})
}

// extractToolResultBlock handles `{"type":"tool_result","content":…}`. Per the
// Anthropic schema `content` is either a bare string or an array of blocks
// (usually text), i.e. exactly the same union collectContentField already
// understands — so it recurses through the SAME walker with the tool ceiling
// inherited. That is what makes "text nested in a tool_result" audit-only
// without a second copy of the block-type switch.
func extractToolResultBlock(block map[string]any, ceiling actionCeiling, depth int, out *[]contentPiece) {
	collectContentFieldCapped(block, "content", ceiling, depth+1, out)
}

// extractToolUseBlock handles `{"type":"tool_use","name":…,"input":{…}}`, whose
// payload is an arbitrary JSON object with no `text` field anywhere — the shape
// arm C of the TOOL-SCOPE case proved no amount of block-type widening reaches.
//
// WHY every string VALUE, rather than a whitelist of known argument names
// (`command`, `file_path`, …): `input` is defined by the TOOL, and tools are
// open-ended — every MCP server ships its own schema. A name whitelist would
// cover Claude Code's built-ins and systematically miss everything else, which
// is the worst possible outcome for a MEASUREMENT phase: the hit-rate numbers
// 方案① will be judged on would describe only the shapes we happened to guess.
// The usual objection to scanning everything ("masking arbitrary tool arguments
// corrupts the tool call") does not apply under ceilingAudit — nothing is ever
// written back. That is exactly why 方案② can afford the maximum-coverage
// extraction 方案① could not.
//
// WHY values only, and WHY joined into ONE piece:
//
//   - Values only, never keys / braces / quotes: serializing the whole object
//     would feed the detector JSON punctuation and field NAMES, perturbing its
//     NLP lane and making the FP numbers unrepresentative of what a real file
//     body or command line looks like. The corpus this phase collects has to
//     resemble the corpus 方案① would act on.
//   - ONE joined piece, not one per string: a `MultiEdit`-shaped input carries
//     two strings per edit, so per-string pieces would mean dozens of Detect
//     IPC round-trips for a single block on the request hot path — and would
//     need a new per-object count cap (with its own truncation signal) to bound
//     the pathological case. Joining reuses the caps that already exist and are
//     already reasoned about: pipeInputCap (16KB over the pipe) and the
//     detector's nlpInputCap. No new mechanism, one round-trip per block.
//
// 🔴 The joined piece is UNWRITABLE (setText nil): a mask verdict cannot be
// written back into N separate JSON nodes from one concatenated string. That is
// consistent only while the ceiling forbids masking — the pairing is asserted by
// TestBlockScanPolicy_UnwritablePiecesCannotBeMaskable, and the dispatcher
// carries a defensive nil check. Raising this row to ceilingFull therefore
// requires replacing the join with per-node pieces first; the fence says so.
func extractToolUseBlock(block map[string]any, ceiling actionCeiling, depth int, out *[]contentPiece) {
	input, ok := block["input"]
	if !ok {
		return
	}
	var sb strings.Builder
	appendJSONStringValues(input, depth+1, &sb)
	if sb.Len() == 0 {
		return
	}
	*out = append(*out, contentPiece{text: sb.String(), ceiling: ceiling, setText: nil})
}

// appendJSONStringValues walks an arbitrary decoded JSON value and appends every
// non-empty string VALUE it reaches, newline-separated. Object keys are visited
// in sorted order so the scanned text (and therefore the content-hash cache key)
// is stable across Go's randomized map iteration.
func appendJSONStringValues(v any, depth int, sb *strings.Builder) {
	if depth > blockNestDepthCap {
		return
	}
	switch t := v.(type) {
	case string:
		if t == "" {
			return
		}
		if sb.Len() > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(t)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			appendJSONStringValues(t[k], depth+1, sb)
		}
	case []any:
		for i := range t {
			appendJSONStringValues(t[i], depth+1, sb)
		}
	}
}

// contentPiece is one scannable text value located in the request envelope,
// paired with a setter that writes a replacement back into the parsed structure.
//
// ceiling caps what the dispatcher may DO with the detector's verdict for this
// piece. 🔴 Its zero value is ceilingAudit (the weakest), so a piece constructed
// without an explicit ceiling can only ever produce an audit event — a forgotten
// field cannot widen the blast radius. Every constructor below states it.
//
// setText is nil for pieces whose scanned text has no single JSON node to write
// back to (the joined tool_use.input blob). A nil setter is only sound while the
// ceiling forbids masking; the pairing is fenced, and the dispatcher checks.
type contentPiece struct {
	setText func(string)
	text    string
	ceiling actionCeiling
}

// extractFilterableContent parses an LLM request body and returns the maskable
// content pieces plus the parsed structure (re-marshal it after mutating pieces).
//
// ok=false when the body is not a JSON object — the caller must then pass the
// request through unfiltered (fail-open; non-LLM bodies are not our concern).
// ok=true with zero pieces means a recognized-but-empty shape (no user text).
func extractFilterableContent(body []byte) (pieces []contentPiece, parsed map[string]any, ok bool) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, nil, false
	}

	// Anthropic top-level system prompt (string or block array). OpenAI carries
	// system inside messages[] instead, so this is simply absent there.
	collectContentField(m, "system", &pieces)

	// messages[].content for both Anthropic and OpenAI chat shapes.
	if msgs, isArr := m["messages"].([]any); isArr {
		for _, mi := range msgs {
			if msg, isObj := mi.(map[string]any); isObj {
				collectContentField(msg, "content", &pieces)
			}
		}
	}

	// OpenAI Responses API (codex): content lives in input[] / input string,
	// system in `instructions` (kept in scope here as the full extractor mirrors
	// system for masking symmetry). See extractUserContent for the live path.
	collectContentField(m, "instructions", &pieces)
	switch in := m["input"].(type) {
	case string:
		if in != "" {
			// Responses API single-turn shorthand: the human's own prose → full ceiling.
			pieces = append(pieces, contentPiece{text: in, ceiling: ceilingFull, setText: func(s string) { m["input"] = s }})
		}
	case []any:
		for _, ii := range in {
			if item, isObj := ii.(map[string]any); isObj {
				collectContentField(item, "content", &pieces)
			}
		}
	}

	return pieces, m, true
}

// extractUserContent extracts the maskable text of every message whose role the
// scan-role policy covers — by default user + assistant, across all turns
// (latest + history). Two incidents shaped this scan set:
//
//   - 2026-06-16 history leak: the user's earlier sensitive input lives in a
//     HISTORY user message and must be re-masked every turn (scanning only the
//     latest turn let it through unmasked from turn 2 on);
//   - 2026-08-08 restore leak (方案 §2.2): response-side placeholder restoration
//     returns the PLAINTEXT to the client, so from turn 2 on that plaintext is
//     replayed inside an ASSISTANT message. Skipping assistant would make masking
//     a first-turn-only feature. See scanRoleSet.
//
// It still SKIPS the system prompt / OpenAI `instructions` unconditionally: those
// are admin-authored directives, and masking them corrupts the agent (the policy
// universe contains "system"/"developer" so an operator CAN opt in, but the
// top-level `system` field is not a message and is never collected here).
//
// Fail-safe role handling (scanRoleSet.scans): a missing/empty role, or a role
// outside the known universe, is ALWAYS scanned — never silently under-scan real
// input. ok=false only when the body is not a JSON object with a messages[] array
// → caller falls back to forwarding unfiltered (same fail-open as before for
// non-chat bodies).
func extractUserContent(body []byte, roles scanRoleSet) (pieces []contentPiece, parsed map[string]any, ok bool) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, nil, false
	}
	if msgs, isArr := m["messages"].([]any); isArr {
		collectUserTurns(msgs, roles, &pieces)
		return pieces, m, true
	}
	// OpenAI Responses API (codex, /v1/responses): the request carries no
	// messages[]; user turns live in input[] and the system prompt in
	// `instructions` (skipped like `system`). input can be a bare string
	// (single-turn shorthand) or an item array whose message items mirror
	// chat messages but with input_text content parts. Without this branch
	// the whole request was "not filterable" → forwarded UNFILTERED, letting
	// codex prompts bypass the compliance scan while conversation audit (a
	// separate, Responses-aware path) still captured them (live incident
	// 2026-07-08; same wire-format class as the audit R20 fix).
	switch in := m["input"].(type) {
	case string:
		if in != "" {
			pieces = append(pieces, contentPiece{
				text: in,
				// The human's own prose (Responses single-turn shorthand) → full ceiling.
				ceiling: ceilingFull,
				setText: func(s string) { m["input"] = s },
			})
		}
		return pieces, m, true
	case []any:
		collectUserTurns(in, roles, &pieces)
		return pieces, m, true
	}
	return nil, m, false
}

// collectUserTurns scans a chat-style item array (Anthropic/OpenAI messages[]
// or Responses API input[]) for the text of every message the scan-role policy
// covers. Role handling lives entirely in scanRoleSet.scans (allow-list over a
// closed universe + fail-safe scan for anything unknown), so adding a role is a
// configuration change rather than an edit here.
func collectUserTurns(items []any, roles scanRoleSet, out *[]contentPiece) {
	for _, mi := range items {
		msg, isObj := mi.(map[string]any)
		if !isObj {
			continue
		}
		role, _ := msg["role"].(string)
		if !roles.scans(role) {
			continue
		}
		collectContentField(msg, "content", out)
	}
}

// extractLatestUserContent extracts ONLY the latest user turn's text — the NEW
// content in a request that resends the full conversation (system + history)
// every turn (OpenClaw, Claude Code, Codex, Cursor all do this). It deliberately
// skips `system` (static, admin-authored) and all prior messages (already scanned
// on their own turn), so the detector scans a few-dozen-byte new message instead
// of re-scanning 10-28KB every request. See Proxy.filterIncremental for the why.
//
// SAFETY (never silently under-scan): returns ok=false — caller MUST fall back to
// a FULL extractFilterableContent scan — on any shape it can't confidently reduce
// to "the human's new input":
//   - non-JSON body,
//   - no messages array / empty,
//   - last message isn't role=="user" (assistant- or tool-terminated agent loop),
//   - last user message carries no scannable text (attachment blocks only —
//     since 2026-08-10 a tool_result-only message DOES yield pieces, at
//     ceilingAudit; see blockScanPolicy).
//
// Mask write-back: the returned pieces' setText closures mutate parsed (the FULL
// body map) in place, so re-marshaling parsed yields the original request with
// only the latest user text masked — identical re-serialization path as the full
// scan.
func extractLatestUserContent(body []byte) (pieces []contentPiece, parsed map[string]any, ok bool) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, nil, false
	}
	msgs, isArr := m["messages"].([]any)
	if !isArr || len(msgs) == 0 {
		return nil, m, false
	}
	last, isObj := msgs[len(msgs)-1].(map[string]any)
	if !isObj {
		return nil, m, false
	}
	if role, _ := last["role"].(string); role != "user" {
		return nil, m, false
	}
	collectContentField(last, "content", &pieces)
	if len(pieces) == 0 {
		return nil, m, false
	}
	return pieces, m, true
}

// collectContentField appends scannable pieces for a field that is either a
// string ("content":"…") or an array of typed blocks ("content":[{"type":"text",
// "text":"…"}, …]). Which block types are extracted, and what the dispatcher is
// allowed to DO with each one's verdict, live together in blockScanPolicy —
// a type absent from that table is skipped entirely.
//
// DELIBERATE EXCLUSIONS (documented so a future reader doesn't "fix" them):
//   - Anthropic `thinking` / `redacted_thinking` blocks carry a `signature` the
//     API verifies when the client replays them; rewriting their text would make
//     the upstream reject the request outright. Fail-open beats a broken request.
//     🔴 The other half of this rule lives on the RESPONSE leg: because these
//     blocks can never be scanned here, restore must never write originals into
//     them either — otherwise the plaintext comes back next turn through the one
//     door that has no lock (S3, 2026-08-09). Enforced by restoreSkipBlockTypes
//     in filter_restore.go; the two are one rule, change them together.
//   - Attachment blocks (document / image / input_image / base64 payloads) carry
//     no natural-language `text` field the detector can act on. Still open.
//
// 🔴 NOT excluded any more: `tool_result` / `tool_use`. They are scanned at
// ceilingAudit since 2026-08-10 (方案②) — see the blockScanPolicy header.
func collectContentField(parent map[string]any, key string, out *[]contentPiece) {
	collectContentFieldCapped(parent, key, ceilingFull, 0, out)
}

// collectContentFieldCapped is collectContentField with an INHERITED ceiling,
// used when the field is nested inside a block that is itself capped (a text
// block inside a tool_result). Every piece is stamped with the tighter of the
// inherited ceiling and its own policy row, so nesting can only ever restrict.
func collectContentFieldCapped(parent map[string]any, key string, inherited actionCeiling, depth int, out *[]contentPiece) {
	if depth > blockNestDepthCap {
		return
	}
	switch v := parent[key].(type) {
	case string:
		// A bare string content is the message's own prose — full ceiling unless
		// something above us already tightened it (tool_result with string content).
		if v != "" {
			*out = append(*out, contentPiece{
				text:    v,
				ceiling: inherited,
				setText: func(s string) { parent[key] = s },
			})
		}
	case []any:
		for _, bi := range v {
			block, isObj := bi.(map[string]any)
			if !isObj {
				continue
			}
			blockType, _ := block["type"].(string)
			rule, scannable := effectiveBlockScanPolicy()[blockType]
			if !scannable {
				continue
			}
			eff := inherited.tighten(rule.ceiling)
			// ceilingOff = the row is switched off: skip it exactly as if it were
			// absent from the table. This is the ONE gate — extraction never runs,
			// so nothing reaches the detector and no event is produced. It is here,
			// on the row's own ceiling, so "which block types" and "what may be done
			// with them" cannot be configured apart (see toolBlockScanMode).
			if eff == ceilingOff {
				continue
			}
			rule.extract(block, eff, depth, out)
		}
	}
}

// topLevelKeys + messageCount are diagnostic helpers for the filter dispatcher's
// "no filterable content" skip log (proxy.filter.skipped). They expose the SHAPE
// of a request the extractor found nothing in — the key signal when a client
// (e.g. OpenClaw) sends a body that masks differently from a hand-rolled curl.
// Nil-safe: parsed is nil when the body was not JSON. (2026-06-13 form-② RCA.)
func topLevelKeys(m map[string]any) []string {
	if m == nil {
		return nil
	}
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func messageCount(m map[string]any) int {
	if m == nil {
		return 0
	}
	if msgs, ok := m["messages"].([]any); ok {
		return len(msgs)
	}
	return 0
}
