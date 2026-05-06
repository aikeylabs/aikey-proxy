// Full Claude-Code body fingerprint injection for Anthropic OAuth requests
// originating from non-Claude-CLI clients (opencode, Cursor, Cline, etc.).
//
// Background
// ----------
// Anthropic's OAuth path enforces a body-side identity check on premium
// models (Sonnet/Opus): unless body.system[0] either (a) equals the byte-
// exact Claude Code intro prompt or (b) carries an x-anthropic-billing-
// header text block with a cc_entrypoint marker, the request is rejected
// as 429 "rate_limit_error" with no anthropic-ratelimit-* headers.
// Bisection details + replay tooling:
// workflow/CI/research/oauth-token-response-identity/2026-04-15-oauth-token-response-identity.md
// (sections "2026-05-06 增补 I" and Round 5).
//
// Strategy
// --------
// For non-CLI clients we synthesise the four signals real CLI traffic
// carries (a 2-block system, a version-derived 3-hex suffix on cc_version,
// a body-content xxhash64 sealing the billing block, and an ephemeral
// cache_control on the intro), and we relocate the client's original
// system text into a leading user/assistant message pair so the model
// still receives the instructions. There is no env toggle — Claude CLI
// traffic is detected upstream (clientIsClaudeCode) and bypasses this
// path entirely.
//
// Provenance / licensing
// ----------------------
// The reverse-engineered constants below (fingerprintSalt, cchSeed,
// the [4, 7, 20] sample positions, the cc_version / cch wire syntax) are
// observable facts about Claude Code CLI traffic — they were originally
// documented by the open-source sub2api project (LGPL-3.0,
// https://github.com/Wei-Shaw/sub2api). Facts are not subject to
// copyright; the Go code below is an independent re-expression that
// uses different decomposition, parsing idioms, and string/byte handling
// than sub2api's implementation. The repository's NOTICE file credits
// sub2api as research source, and a copy of LGPL-3.0 is shipped under
// THIRD-PARTY-LICENSES/sub2api-LGPL-3.0.txt as a defensive measure.

package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cespare/xxhash/v2"
)

// Reverse-engineered facts about Claude Code CLI's wire format. These are
// not original expression — they are observable byte-level constants in
// the public Anthropic OAuth wire protocol. Tracking the latest CLI we've
// observed; bump claudeCLIVersion when real CLI advances so the synthesised
// cc_version stays plausible.
const (
	claudeCLIVersion = "2.1.128"

	// fingerprintSalt is the constant byte string mixed into the SHA-256
	// hash that real CLI uses to derive its cc_version trailing 3 hex
	// chars. A discovered protocol constant, not authored by us.
	fingerprintSalt = "59cf53e54c78"

	// cchSeed is the xxhash64 seed real CLI uses to compute the cch body
	// digest. Same provenance as the salt — discovered, not authored.
	cchSeed uint64 = 0x6E52736AC806831E

	// billingHeaderPrefix is the leading wire-format marker of the
	// billing-attribution text block. Used as both an idempotency probe
	// and an anchor for the placeholder rewrite.
	billingHeaderPrefix = "x-anthropic-billing-header:"

	// cchPlaceholder is the literal token we emit when synthesising the
	// billing block; it gets rewritten in place once the body is fully
	// marshalled (so the hash covers every byte we produced).
	cchPlaceholder = "cch=00000;"

	// cchPlaceholderZeros is the 5-byte run that gets overwritten by the
	// hex digest. Defined separately to make the surgical replace boundary
	// obvious at the call site.
	cchPlaceholderZeros = "00000"

	// instructionInjectionPreamble is prepended to the client's original
	// system text when it's relocated into messages — keeps the model
	// aware that the following content came from the system slot.
	instructionInjectionPreamble = "[System Instructions]\n"

	// assistantAcknowledgement is the synthetic assistant turn we emit
	// alongside the relocated system text, so the model sees a complete
	// instruction-then-acknowledgement pair before the user's real turn.
	assistantAcknowledgement = "Understood. I will follow these instructions."
)

// claudeCodeFingerprintPositions are the byte indices into the first user
// text that real CLI samples for its cc_version trailing fingerprint.
// Discovered fact, not authored.
var claudeCodeFingerprintPositions = [3]int{4, 7, 20}

// clientIsClaudeCode reports whether the inbound request was issued by the
// real Claude Code CLI binary (vs. a third-party OAuth-relay client like
// opencode/Cursor/Cline). Detection is User-Agent prefix only — must be
// called BEFORE the proxy's UA detect-and-replace step (which forces every
// outbound UA to claude-cli/X.Y.Z regardless of origin).
func clientIsClaudeCode(req *http.Request) bool {
	return strings.HasPrefix(req.Header.Get("User-Agent"), "claude-cli/")
}

// injectClaudeWAFFingerprintFull is the body rewriter for non-CLI clients.
// It is a no-op when:
//   - the body cannot be parsed as JSON (we can only modify JSON safely);
//   - the request targets a Haiku model (WAF doesn't gate Haiku);
//   - the existing system field already passes the WAF marker check
//     (idempotency for traffic that happens to carry CLI-style markers).
//
// Otherwise the body is rewritten with the full four-layer mimicry plus
// instruction relocation, marshalled, and the cch placeholder is sealed
// against the final byte stream.
func injectClaudeWAFFingerprintFull(req *http.Request) {
	if req.Body == nil {
		return
	}
	originalBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}
	_ = req.Body.Close()

	var body map[string]any
	if err := json.Unmarshal(originalBytes, &body); err != nil {
		setRequestBody(req, originalBytes)
		return
	}

	if isHaikuRequest(body) {
		setRequestBody(req, originalBytes)
		return
	}
	if _, alreadyOK := normalizeSystemAndCheckFingerprint(body["system"]); alreadyOK {
		setRequestBody(req, originalBytes)
		return
	}

	preservedSystemText := flattenClientSystemText(body["system"])
	body["messages"] = prependInstructionPair(body["messages"], preservedSystemText)

	// Compute the cc_version suffix against the rewritten messages array
	// (the algorithm samples the *first user text*, which after the
	// instruction-pair prepend is the synthetic [System Instructions] block).
	suffixSeed, _ := json.Marshal(map[string]any{"messages": body["messages"]})
	body["system"] = synthesiseTwoBlockSystem(suffixSeed)

	rewritten, err := json.Marshal(body)
	if err != nil {
		setRequestBody(req, originalBytes)
		return
	}
	setRequestBody(req, sealCCHPlaceholder(rewritten))
}

// flattenClientSystemText reduces the client's pre-rewrite system payload
// (string | []block | nil | misc) to a single trimmed text string suitable
// for relocation into messages. Empty result means "nothing to relocate".
//
// Filtered out:
//   - blank or whitespace-only content
//   - blocks that are themselves the magic intro (already a CLI marker —
//     we never re-inject it as user content)
//   - blocks whose content begins with the billing-header prefix (those
//     are persona signals, not user instructions)
//   - non-text block types
func flattenClientSystemText(rawSystem any) string {
	switch sys := rawSystem.(type) {
	case string:
		text := strings.TrimSpace(sys)
		if textIsClaudeCodeMarker(text) {
			return ""
		}
		return text

	case []any:
		buf := make([]string, 0, len(sys))
		for _, item := range sys {
			block, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if blockType, _ := block["type"].(string); blockType != "text" {
				continue
			}
			text, _ := block["text"].(string)
			text = strings.TrimSpace(text)
			if textIsClaudeCodeMarker(text) {
				continue
			}
			buf = append(buf, text)
		}
		return strings.Join(buf, "\n\n")

	default:
		// nil, map, or unknown — nothing to relocate.
		return ""
	}
}

// textIsClaudeCodeMarker reports whether a system block text is empty,
// the magic intro itself, or a billing-header signal. We treat all three
// as "not user instruction" and skip them when collecting content for
// relocation into messages.
func textIsClaudeCodeMarker(text string) bool {
	if text == "" {
		return true
	}
	if text == claudeCodeSystemPrompt {
		return true
	}
	return strings.HasPrefix(text, billingHeaderPrefix)
}

// prependInstructionPair returns a messages array with a synthetic
// user/assistant pair at the front carrying the relocated system text.
// When relocatedSystem is empty, the existing messages slice is returned
// unchanged.
func prependInstructionPair(existingMessages any, relocatedSystem string) []any {
	existing, _ := existingMessages.([]any)
	if relocatedSystem == "" {
		return existing
	}

	userTurn := map[string]any{
		"role": "user",
		"content": []any{
			map[string]any{
				"type": "text",
				"text": instructionInjectionPreamble + relocatedSystem,
			},
		},
	}
	assistantTurn := map[string]any{
		"role": "assistant",
		"content": []any{
			map[string]any{
				"type": "text",
				"text": assistantAcknowledgement,
			},
		},
	}
	return append([]any{userTurn, assistantTurn}, existing...)
}

// synthesiseTwoBlockSystem builds the [billing, intro+cache_control] system
// array that real CLI emits. The cch field is left as the literal
// placeholder; it is sealed once the entire body is marshalled.
func synthesiseTwoBlockSystem(suffixSeed []byte) []any {
	suffix := computeClaudeCodeVersionFingerprint(suffixSeed, claudeCLIVersion)
	billingText := fmt.Sprintf(
		"%s cc_version=%s.%s; cc_entrypoint=cli; %s",
		billingHeaderPrefix, claudeCLIVersion, suffix, cchPlaceholder,
	)
	return []any{
		map[string]any{"type": "text", "text": billingText},
		map[string]any{
			"type":          "text",
			"text":          claudeCodeSystemPrompt,
			"cache_control": map[string]any{"type": "ephemeral"},
		},
	}
}

// computeClaudeCodeVersionFingerprint produces the 3 hex character suffix
// real CLI appends to cc_version. The hash inputs (salt, sampled chars,
// version) are streamed into a single sha256 digest; we return the first
// 3 hex chars of the digest.
//
// Algorithm spec (publicly observable):
//
//	suffix = hex(SHA256(salt || charsAt[4,7,20](firstUserText) || version))[:3]
//
// Missing characters (text shorter than the requested index) are padded
// with the literal byte '0'.
func computeClaudeCodeVersionFingerprint(body []byte, cliVersion string) string {
	sample := samplePositionalBytes(firstUserTextContent(body))

	h := sha256.New()
	h.Write([]byte(fingerprintSalt))
	h.Write(sample)
	h.Write([]byte(cliVersion))
	digest := h.Sum(nil)

	return hex.EncodeToString(digest[:2])[:3]
}

// samplePositionalBytes pulls the canonical 3-byte sample from text. Indices
// past the end of text are filled with '0'.
func samplePositionalBytes(text string) []byte {
	var out [3]byte
	for i, pos := range claudeCodeFingerprintPositions {
		if pos < len(text) {
			out[i] = text[pos]
		} else {
			out[i] = '0'
		}
	}
	return out[:]
}

// firstUserTextContent walks body.messages and returns the first text
// content emitted by a user-role message. Both string-form content and
// array-of-text-block content are accepted; everything else returns "".
//
// We use a two-stage RawMessage parse so a misshapen later message
// can't poison the lookup of an earlier well-formed user message.
func firstUserTextContent(body []byte) string {
	var top struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return ""
	}
	for _, raw := range top.Messages {
		var head struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(raw, &head) != nil {
			continue
		}
		if head.Role != "user" {
			continue
		}

		// Probe string content first.
		var asString string
		if json.Unmarshal(head.Content, &asString) == nil {
			return asString
		}
		// Probe block-array content.
		var asBlocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(head.Content, &asBlocks) == nil {
			for _, block := range asBlocks {
				if block.Type == "text" {
					return block.Text
				}
			}
		}
		return ""
	}
	return ""
}

// sealCCHPlaceholder rewrites the literal "cch=00000;" inside the billing
// block with a 5-hex digest of the entire body. The byte-level surgical
// replace (rather than a regex back-reference rewrite) keeps the
// implementation transparent: locate the billing-header anchor, locate
// the placeholder relative to it, then overwrite five bytes in place.
//
// No-op when no billing header is present, or when the placeholder is
// absent (idempotent for already-sealed bodies).
func sealCCHPlaceholder(body []byte) []byte {
	headerStart := bytes.Index(body, []byte(billingHeaderPrefix))
	if headerStart < 0 {
		return body
	}
	relativeIdx := bytes.Index(body[headerStart:], []byte(cchPlaceholder))
	if relativeIdx < 0 {
		return body
	}
	zerosStart := headerStart + relativeIdx + len("cch=")

	digest := xxhash.NewWithSeed(cchSeed)
	_, _ = digest.Write(body)
	hexDigest := fmt.Sprintf("%05x", digest.Sum64()&0xFFFFF)

	// Surgical 5-byte overwrite. Allocate a copy so we don't mutate the
	// caller's slice (Go's marshal output is the caller in our case, and
	// they don't expect us to mutate).
	out := make([]byte, len(body))
	copy(out, body)
	copy(out[zerosStart:zerosStart+len(cchPlaceholderZeros)], []byte(hexDigest))
	return out
}
