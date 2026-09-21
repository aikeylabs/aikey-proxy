package proxy

// canned_answer_variable.go — the ONE whitelisted variable a canned answer may
// carry: `{{机密内容}}`, expanded to 「命中类别 + 打码片段」.
//
// spec: R-compliance-canned-answer-10 代答文案支持唯一白名单变量（取代 -3 的
//
//	「一律不插值」那一句；-3 的其余部分原封不动仍然生效）
//	需求包 roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
//	openspec/specs/compliance-canned-answer/spec.md
//
// # 这解决什么问题
//
// 2026-09-20 用户拍板：员工收到「该消息涉及机密，请修改后重新发出」时，光有这句
// 话不知道要改哪里——一句不带线索的拒绝会让人**反复试**，而每试一次就把剩下的敏感
// 内容再往边界推一次，正是代答本来要消灭的行为。所以代答需要说清楚「是哪几类、大
// 概是哪几个值」。
//
// # 🔴 这反转了一条已实施的红线，反转是用户拍板的
//
// R-compliance-canned-answer-3 原文：「代答文案 SHALL 原样输出，SHALL NOT 做任何
// 变量替换……命中片段 SHALL NOT 出现在代答响应体中」。本文件是该句的**唯一豁免**，
// 边界由控制者定死（2026-09-20）：
//
//  1. **只有一个变量**。其余任何 `{{...}}` 原样输出，包括 `{{机密内容 }}` 这种差
//     一个字符的写法——白名单比对的是**完整字面量**，不是前缀、不是正则。
//  2. **绝不输出未打码的原文**。片段一律过 maskHitFragment，而它**只可能**露出
//     数字（见那个函数的红线注释）。
//  3. **不改 wire，不新增内容派生值**。片段是 proxy 本地拿自己手上的原文 + finding
//     的偏移切出来的（复用既有的 hitValue，与 R-compliance-grading-16 的计数走同
//     一条路），算完即丢：不进事件、不进日志、不进缓存、不落库。
//  4. **有上限**。命中很多时不把整段内容拼回去，见 cannedAnswerMaxHits /
//     cannedAnswerFragmentMaxRunes。
//
// # 残留风险（已向用户讲明，2026-09-20，写在这里是因为它们不是 bug 而是取舍）
//
//   - ① 代答响应会进入客户端的会话历史，可能被第三方 agent 记录或上传；
//   - ② 非本人发起的链路（服务端批处理 / 共享账号）收到回显的人可能不是原发送者；
//   - ③ 打码片段泄露值的**长度与首尾数字**。
//
// 这三条的共同前提是「代答回给的是这条消息的发送者本人，原文本来就是他自己输入
// 的」。前提若不再成立（例如出现代发链路），本能力要重新评估，不是自动继续有效。

import (
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"unicode"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// cannedAnswerConfidentialVar is THE whitelisted token, spelled here and nowhere
// else (fence: TestFence_ConfidentialVariableHasOneSpelling). A second
// hand-written copy is how "one variable" quietly becomes "two, one of which
// nobody fenced".
const cannedAnswerConfidentialVar = "{{机密内容}}"

const (
	// cannedAnswerMaxHits caps HOW MANY hits the expansion names. Beyond it the
	// list is truncated and says how many there were in total (「等 N 处」).
	//
	// WHY 5: the expansion is inserted into a sentence a human reads in one
	// glance; a list longer than that stops being actionable and starts being
	// the content pasted back. 5 × (类别名 + ≤24 字符片段) ≈ 200 bytes, the same
	// order of magnitude as the sibling bound on any single piece of content the
	// compliance chain is allowed to carry (detector maxRawSnippetBytes = 512) —
	// so the whole expansion stays under a cap this domain already lives with.
	cannedAnswerMaxHits = 5

	// cannedAnswerFragmentMaxRunes caps the LENGTH of one fragment. Taken from
	// the detector's snippetWindowRunes (24) — the size that domain already
	// decided is "enough for a human to recognize, small enough to bound the
	// exposure".
	cannedAnswerFragmentMaxRunes = 24

	// cannedAnswerRevealRunes is how many runes at each end may be revealed —
	// and only ever the DIGITS among them.
	cannedAnswerRevealRunes = 4

	// cannedAnswerMinDigitsToReveal is the floor that decides whether a value is
	// a structured identifier at all.
	//
	// 🔴 THIS NUMBER IS THE WHOLE SAFETY ARGUMENT, so it gets the whole reason.
	// A "4 前 4 后" rule applied to natural language would echo half a sentence
	// ("John" + "mith", "上海市浦" + "路12号"). Requiring 10 digits means only
	// values shaped like an account number / ID card / phone / card number ever
	// reveal anything, and what they reveal is digits — which is what the user's
	// 2026-09-20 example asked for (3301**********1234). Everything else — names,
	// addresses, violation phrases, API keys, emails — is masked whole.
	cannedAnswerMinDigitsToReveal = 10
)

// cannedAnswerHit is one entry of the expansion. 🔴 It never holds a raw value:
// the masking happens where the value is sliced, so no caller can be handed the
// original by accident.
type cannedAnswerHit struct {
	// name is the TENANT'S OWN word for this kind of data — the last segment of
	// the classification leaf path the grading verdict stamped on the finding
	// ("个人金融信息/C2 身份标识信息/身份证号" → "身份证号"). Empty when the hit
	// carries no leaf (ungraded, or a personal-route count projection, which has
	// no leaf_path on the wire); the renderer then uses a generic term.
	//
	// WHY the leaf and not an entity_type dictionary: the leaf name is what the
	// administrator typed into the console's classification tree, so it is
	// already the 名词字典 for this tenant, in this tenant's language, with no
	// second table to hand-copy into this repository (this package has been bitten
	// four times by hand-copied relays dropping fields).
	name string
	// fragment is ALWAYS masked — see maskHitFragment.
	fragment string
}

// collectCannedAnswerHits turns this request's findings into the entries the
// expansion may name. Distinct BY VALUE, in first-seen order.
//
// 🔴 CONFIRMED HITS ONLY. An unconfirmed hit is a maybe the evidence gate
// rejected; naming it would tell the employee "your 身份证号 …" about something
// that is not one. Same reason the escalation counter refuses to count them
// (escalation.go countsTowardEscalation / R-compliance-grading-16).
//
// Dedup is by RAW VALUE and not by fragment: two different values can mask to
// the same stars, and collapsing them would undercount 「等 N 处」.
func collectCannedAnswerHits(pieces []contentPiece, findings [][]Finding, events [][]byte) []cannedAnswerHit {
	var out []cannedAnswerHit
	seen := make(map[string]struct{})
	for i := range findings {
		if i >= len(pieces) {
			// A findings row with no piece has no text to slice against. The
			// desync it signals is already surfaced by the escalation counter's
			// `skipped` (escalation.go); repeating the WARN here would double-
			// report one defect.
			continue
		}
		var names []string
		if i < len(events) {
			names = decodeEventLeafNames(events[i])
		}
		for j, f := range findings[i] {
			if !f.Confirmed {
				continue
			}
			value, ok := hitValue(pieces[i].text, f)
			if !ok || value == "" {
				continue
			}
			if _, dup := seen[value]; dup {
				continue
			}
			seen[value] = struct{}{}
			name := ""
			if j < len(names) {
				name = names[j]
			}
			out = append(out, cannedAnswerHit{
				name:     name,
				fragment: maskHitFragment(value),
			})
		}
	}
	return out
}

// decodeEventLeafNames reads one leaf NAME per finding out of the compliance
// event, index-aligned with decodeEventFindings' output.
//
// 🔴 WHY A SECOND DECODE INSTEAD OF A FIELD ON proxy.Finding: that type is the
// REQUEST COUNTER'S reader and is shared by both routes, and
// TestCountProjection_TagsMatchProxyFinding pins it field-for-field against
// pipewire.CountedFinding — the personal-route projection, which is content-free
// by construction and carries no leaf_path. Adding the field there would have
// meant either widening that wire (forbidden by the TODO-178 boundary: 「不改
// wire」) or leaving a field on the counter's reader that silently reads zero on
// one of the two routes, which is exactly the failure that fence exists to
// prevent. So the canned answer decodes what only IT needs, from the same JSON,
// and the counter's contract is untouched.
//
// Alignment holds by construction: both decoders read the SAME `findings` array
// of the SAME document in array order. A shorter/absent result is tolerated by
// the caller (unnamed hits render as the generic term) rather than shifting
// names onto the wrong hit.
//
// Absent on a personal-route count projection (no leaf_path on that wire) and on
// an ungraded hit — both legitimately yield "".
func decodeEventLeafNames(eventJSON []byte) []string {
	if len(eventJSON) == 0 {
		return nil
	}
	var doc struct {
		Findings []struct {
			LeafPath string `json:"leaf_path"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(eventJSON, &doc); err != nil {
		return nil
	}
	out := make([]string, len(doc.Findings))
	for i, f := range doc.Findings {
		out[i] = lastLeafSegment(f.LeafPath)
	}
	return out
}

// lastLeafSegment returns the tenant's own name for a classification leaf.
func lastLeafSegment(leafPath string) string {
	if i := strings.LastIndex(leafPath, "/"); i >= 0 {
		leafPath = leafPath[i+1:]
	}
	return strings.TrimSpace(leafPath)
}

// maskHitFragment is THE masking primitive for this feature — one outlet, so
// "what does a fragment look like" can never be re-derived at a second call
// site and drift.
//
// 🔴 IT CAN ONLY EVER REVEAL AN ASCII DIGIT. Every rune that is not a digit
// becomes '*', including inside the revealed head and tail, and nothing is
// revealed at all unless the value carries at least cannedAnswerMinDigitsToReveal
// digits. So a name, an address, a violation phrase, an email or an API key
// comes back as stars whatever its shape — the reveal rule cannot be talked into
// echoing prose.
//
// WHY NOT the detector's planner (the existing masker): that one replaces a hit
// with a fixed token ({{IDCARD}}), which is the right answer for text that goes
// ON to the model and the wrong one here — a fragment that says nothing about
// WHICH of three ID cards to fix would leave the user exactly where a bare
// refusal left them. It also lives in another module (ai-compliance-detector),
// and copying its table over here is the hand-copied-relay failure this
// repository has already hit four times. So: one primitive, here, with a rule
// narrow enough to state in one sentence.
func maskHitFragment(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return ""
	}
	digits := 0
	for _, r := range runes {
		if isASCIIDigit(r) {
			digits++
		}
	}
	head, tail := 0, 0
	if digits >= cannedAnswerMinDigitsToReveal && len(runes) > 2*cannedAnswerRevealRunes {
		head, tail = cannedAnswerRevealRunes, cannedAnswerRevealRunes
	}
	stars := len(runes) - head - tail
	if maxStars := cannedAnswerFragmentMaxRunes - head - tail; stars > maxStars {
		stars = maxStars
	}
	if stars < 1 {
		// A fragment that showed no mask at all would read as the original.
		stars = 1
	}

	var b strings.Builder
	keep := func(from, count int) {
		for i := from; i < from+count; i++ {
			if isASCIIDigit(runes[i]) {
				b.WriteRune(runes[i])
				continue
			}
			b.WriteRune('*')
		}
	}
	keep(0, head)
	b.WriteString(strings.Repeat("*", stars))
	keep(len(runes)-tail, tail)
	return b.String()
}

func isASCIIDigit(r rune) bool { return r >= '0' && r <= '9' }

// renderCannedAnswerText substitutes the ONE whitelisted variable and returns
// the sentence the client will read.
//
// 🔴 NO TEMPLATE ENGINE AND NO substitution PRIMITIVE. The scan walks the
// administrator's text once, copying it, and swaps only exact occurrences of the
// whitelisted literal. Written with strings.Index rather than strings.ReplaceAll
// for two reasons that both matter: the rendered list is appended to the OUTPUT
// and never re-scanned (so a tenant leaf named like the token cannot recurse),
// and the guardrail's red-line fence forbids substitution primitives on this
// path by name (compliance_guardrail_response_fence_test.go
// interpolationPrimitives) — that ban stays in force, which is the point.
//
// A text WITHOUT the token is returned unchanged, byte for byte: an organization
// that never uses the variable sees exactly what it saw before
// (R-compliance-canned-answer-3.S1 is still the rule for every other token).
func renderCannedAnswerText(text string, hits []cannedAnswerHit, logger *slog.Logger) string {
	if !strings.Contains(text, cannedAnswerConfidentialVar) {
		return text
	}
	zh := containsCJK(text)
	if len(hits) == 0 {
		// The variable was used but this request produced no sliceable confirmed
		// hit (offsets outside the piece, an unconfirmed-only request, a detector
		// that sent no findings). The user still gets a sentence that reads, and
		// the operator gets told the expansion was empty — a silent generic term
		// is how "the variable stopped working" would go unnoticed for months.
		logger.Warn("filter: canned answer used the confidential-content variable but this request "+
			"produced no readable confirmed hit; expanded to the generic term",
			"event.name", observability.EventProxyFilterCannedAnswerVariableEmpty)
	}
	rendered := renderCannedAnswerHits(hits, zh)

	var b strings.Builder
	rest := text
	for {
		i := strings.Index(rest, cannedAnswerConfidentialVar)
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		b.WriteString(rest[:i])
		b.WriteString(rendered)
		rest = rest[i+len(cannedAnswerConfidentialVar):]
	}
}

// renderCannedAnswerHits formats the list, capped, in the language of the
// sentence it is being inserted into.
//
// WHY the language follows the ADMINISTRATOR'S TEXT and not a config: the
// expansion is a fragment of that sentence. Deciding it anywhere else produces
// "该消息涉及机密，请修改后重新发出：ID number 1234****9876" — a sentence in two
// languages, which no locale setting can fix because the other half was typed by
// hand. The tenant's own leaf names come out in whatever language the
// administrator named them, which is the same answer for the same reason.
func renderCannedAnswerHits(hits []cannedAnswerHit, zh bool) string {
	generic := "sensitive content"
	sep := ", "
	if zh {
		generic = "敏感信息"
		sep = "、"
	}
	if len(hits) == 0 {
		return generic
	}
	shown := hits
	if len(shown) > cannedAnswerMaxHits {
		shown = shown[:cannedAnswerMaxHits]
	}
	parts := make([]string, 0, len(shown))
	for _, h := range shown {
		name := h.name
		if name == "" {
			name = generic
		}
		parts = append(parts, name+" "+h.fragment)
	}
	out := strings.Join(parts, sep)
	if len(hits) > len(shown) {
		// 🔴 N is the TOTAL, not the remainder: 「等 9 处」 reads as "nine in all"
		// in Chinese, and an employee needs to know how much is left to fix, not
		// how much this sentence left out.
		if zh {
			out += "…等 " + strconv.Itoa(len(hits)) + " 处"
		} else {
			out += ", " + strconv.Itoa(len(hits)) + " in total"
		}
	}
	return out
}

// containsCJK reports whether the administrator wrote this sentence in a CJK
// language. One test, not a locale negotiation: the only thing being decided is
// which separator and which generic term read correctly inside THIS sentence.
func containsCJK(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) ||
			unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r) {
			return true
		}
	}
	return false
}
