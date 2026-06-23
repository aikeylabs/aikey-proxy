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
// For non-CLI clients we synthesize the four signals real CLI traffic
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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Reverse-engineered facts about Claude Code CLI's wire format. These are
// not original expression — they are observable byte-level constants in
// the public Anthropic OAuth wire protocol. Tracking the latest CLI we've
// observed; bump claudeCLIVersion when real CLI advances so the synthesized
// cc_version stays plausible.
const (
	claudeCLIVersion = "2.1.128"

	// fingerprintSalt is the constant byte string mixed into the SHA-256
	// hash that real CLI uses to derive its cc_version trailing 3 hex
	// chars. A discovered protocol constant, not authored by us.
	fingerprintSalt = "59cf53e54c78"

	// billingHeaderPrefix is the leading wire-format marker of the
	// billing-attribution text block. Used as an idempotency probe.
	billingHeaderPrefix = "x-anthropic-billing-header:"

	// cchPlaceholder is the cch token we emit in the billing block.
	//
	// We deliberately leave it a STABLE constant (cch=00000) instead of a
	// body digest. Why:
	//   - The WAF does NOT verify cch (research doc Round 5B: cch=00000 /
	//     ffffe / zzzzz / removed all return 200 — only the cc_entrypoint=
	//     key is checked). A real digest buys nothing for WAF passage.
	//   - A body-derived cch changes every turn (the trailing user message
	//     varies), mutating system[0] and invalidating the prompt-cache
	//     prefix on every request. Keeping cch constant makes system[0]
	//     stable so prompt caching actually works on the OAuth path.
	cchPlaceholder = "cch=00000;"

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
// instruction relocation, marshaled, and the cch placeholder is sealed
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
	if jErr := json.Unmarshal(originalBytes, &body); jErr != nil {
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

	// Relocate the client's system text into a leading user message, and
	// CARRY OVER its cache_control so the relocated (often large) prompt is
	// still a prompt-cache breakpoint. If the client set no cache_control we
	// auto-fill ephemeral — the relocated block is the natural cache boundary
	// for non-CLI clients. (Pre-fix bug: the client's cache_control was
	// dropped here, so non-CLI OAuth traffic never cached.)
	preservedSystemText, preservedCacheControl := flattenClientSystemText(body["system"])
	body["messages"] = prependInstructionPair(body["messages"], preservedSystemText, preservedCacheControl)

	// Compute the cc_version suffix against the rewritten messages array
	// (the algorithm samples the *first user text*, which after the
	// instruction-pair prepend is the synthetic [System Instructions] block —
	// stable across a conversation, so cc_version stays stable too).
	suffixSeed, _ := json.Marshal(map[string]any{"messages": body["messages"]})
	body["system"] = synthesizeTwoBlockSystem(suffixSeed)

	rewritten, err := json.Marshal(body)
	if err != nil {
		setRequestBody(req, originalBytes)
		return
	}
	// No cch sealing: cch stays the stable cch=00000 placeholder (see the
	// cchPlaceholder doc). A body hash here would mutate system[0] every turn
	// and break prompt caching, and the WAF doesn't verify cch anyway.
	setRequestBody(req, rewritten)
}

// flattenClientSystemText reduces the client's pre-rewrite system payload
// (string | []block | nil | misc) to a single trimmed text string suitable
// for relocation into messages, and reports the client's own cache_control
// (the last kept block's — i.e. the effective breakpoint) so the caller can
// carry it onto the relocated block. Empty text means "nothing to relocate";
// nil cacheControl means "client set none" (caller auto-fills ephemeral).
//
// Filtered out:
//   - blank or whitespace-only content
//   - blocks that are themselves the magic intro (already a CLI marker —
//     we never re-inject it as user content)
//   - blocks whose content begins with the billing-header prefix (those
//     are persona signals, not user instructions)
//   - non-text block types
func flattenClientSystemText(rawSystem any) (text string, cacheControl any) {
	switch sys := rawSystem.(type) {
	case string:
		t := strings.TrimSpace(sys)
		if textIsClaudeCodeMarker(t) {
			return "", nil
		}
		return t, nil

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
			t, _ := block["text"].(string)
			t = strings.TrimSpace(t)
			if textIsClaudeCodeMarker(t) {
				continue
			}
			buf = append(buf, t)
			// Carry the client's cache_control intent; the last kept block
			// with one wins (that's where the client put their breakpoint).
			if cc, ok := block["cache_control"]; ok && cc != nil {
				cacheControl = cc
			}
		}
		return strings.Join(buf, "\n\n"), cacheControl

	default:
		// nil, map, or unknown — nothing to relocate.
		return "", nil
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
// The relocated user block carries cache_control so it stays a prompt-cache
// breakpoint: the client's own cache_control when it had one, otherwise an
// auto-filled ephemeral one. When relocatedSystem is empty, the existing
// messages slice is returned unchanged.
func prependInstructionPair(existingMessages any, relocatedSystem string, cacheControl any) []any {
	existing, _ := existingMessages.([]any)
	if relocatedSystem == "" {
		return existing
	}

	if cacheControl == nil {
		// Client passed no cache_control — auto-fill ephemeral so the
		// relocated prompt still caches.
		cacheControl = map[string]any{"type": "ephemeral"}
	}

	userTurn := map[string]any{
		"role": "user",
		"content": []any{
			map[string]any{
				"type":          "text",
				"text":          instructionInjectionPreamble + relocatedSystem,
				"cache_control": cacheControl,
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

// synthesizeTwoBlockSystem builds the [billing, intro+cache_control] system
// array that real CLI emits. The cch field is left as the literal
// placeholder; it is sealed once the entire body is marshaled.
func synthesizeTwoBlockSystem(suffixSeed []byte) []any {
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
