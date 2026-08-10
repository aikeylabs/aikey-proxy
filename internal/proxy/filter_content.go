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

// contentPiece is one maskable text value located in the request envelope,
// paired with a setter that writes a replacement back into the parsed structure.
type contentPiece struct {
	setText func(string)
	text    string
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
			pieces = append(pieces, contentPiece{text: in, setText: func(s string) { m["input"] = s }})
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
				text:    in,
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
//   - last user message carries no scannable text (image / tool_result only).
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

// collectContentField appends maskable pieces for a field that is either a
// string ("content":"…") or an array of typed blocks ("content":[{"type":"text",
// "text":"…"}, …]). Non-text blocks (image / tool_use / tool_result / …) and
// null content are skipped — only natural-language text is sent to the hook.
//
// DELIBERATE EXCLUSIONS (documented so a future reader doesn't "fix" them):
//   - Anthropic `thinking` / `redacted_thinking` blocks carry a `signature` the
//     API verifies when the client replays them; rewriting their text would make
//     the upstream reject the request outright. Fail-open beats a broken request.
//     🔴 The other half of this rule lives on the RESPONSE leg: because these
//     blocks can never be scanned here, restore must never write originals into
//     them either — otherwise the plaintext comes back next turn through the one
//     door that has no lock (S3, 2026-08-09). Enforced by reasoningBlockTypes in
//     filter_restore.go; the two are one rule, change them together.
//   - `tool_result` / `tool_use` blocks nest their payload under their own
//     schema (not a flat `text` string); scanning them is a separate decision
//     (the tool/function scan roles exist for it) and is out of P4's scope.
func collectContentField(parent map[string]any, key string, out *[]contentPiece) {
	switch v := parent[key].(type) {
	case string:
		if v != "" {
			*out = append(*out, contentPiece{
				text:    v,
				setText: func(s string) { parent[key] = s },
			})
		}
	case []any:
		for _, bi := range v {
			block, isObj := bi.(map[string]any)
			if !isObj {
				continue
			}
			// "text" = Anthropic/OpenAI chat content block; "input_text" = OpenAI
			// Responses API user content part (codex); "output_text" = the
			// Responses API ASSISTANT content part, i.e. how a replayed model
			// reply carries its text in input[].
			//
			// output_text was added by P4 (2026-08-08): the scan-role policy now
			// covers assistant, but on the Responses wire an assistant item's text
			// sits in output_text, so without this the assistant turn matched the
			// role filter and then yielded ZERO pieces — the restore leak (方案
			// §2.2) would have stayed open for codex/Responses clients while the
			// Anthropic/chat shapes were fixed. Same wire-format class as the
			// 2026-07-08 input_text incident.
			//
			// Non-text blocks (image / input_image / tool_use / tool_result /
			// thinking) are skipped — see the exclusions note above.
			switch t, _ := block["type"].(string); t {
			case "text", "input_text", "output_text":
			default:
				continue
			}
			txt, isStr := block["text"].(string)
			if !isStr || txt == "" {
				continue
			}
			b := block // capture this block for the setter closure
			*out = append(*out, contentPiece{
				text:    txt,
				setText: func(s string) { b["text"] = s },
			})
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
