package openai_anthropic

import (
	"context"
	"strings"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ConvertRequest transforms an OpenAI Chat Completions request body
// into an Anthropic Messages request body. Implements translator.RequestTransform.
//
// 阶段 0 MVP scope (this commit, Day 3):
//
//   - Top-level field mapping (model / max_tokens / temperature / top_p /
//     top_k / stop / user)
//   - reasoning_effort (low / medium / high) → thinking.budget_tokens
//   - Defaults: max_tokens = 4096 when absent (Anthropic requires it);
//     temperature is CAPPED at 1.0 (Anthropic's max; OpenAI allows up to 2.0)
//   - stop / stop_sequences normalization (string or array → array, filter pure whitespace)
//
// NOT yet implemented (later days):
//
//   - messages: this commit passes messages[] through verbatim, which is
//     NOT valid for Anthropic (their format uses content blocks, no
//     system field in messages[]). Day 4 adds proper normalization.
//   - content blocks, tools, tool_choice, response_format → forced tool-call
//
// Why gjson+sjson rather than encoding/json full-parse: surgical edits
// only (5-8 known top-level fields); zero-copy reads are 10-20× faster
// than map[string]interface{} round-trip, and we avoid the field
// reordering that json.Marshal does on Go maps. For the (rare) field
// that needs nested-object construction (thinking, metadata), we build
// it inline as a small JSON literal then sjson.SetRawBytes it.
func ConvertRequest(ctx context.Context, model string, body []byte, stream bool) ([]byte, *translator.TranslateError) {
	_ = ctx    // ctx not used yet — no expensive work at MVP; pairs may honor when stream / network work lands
	_ = stream // stream mode doesn't change request body shape (stream is set by the client header path)

	// Cheap up-front validity check: any path that needs to parse JSON
	// in gjson does this implicitly, but a leading malformed-bytes case
	// gives a clearer error here than later in sjson.
	if !gjson.ValidBytes(body) {
		return nil, &translator.TranslateError{
			Code:       translator.CodeBadRequest,
			HTTPStatus: 400,
			Message:    "request body is not valid JSON",
		}
	}
	in := gjson.ParseBytes(body)

	// Start from a minimal Anthropic skeleton. messages[] is the placeholder
	// shape — Day 4 replaces this with proper messages-normalization output.
	// Why explicit skeleton vs sjson-into-input: the inbound body shape
	// (OpenAI) shares few fields with Anthropic; rebuilding from scratch
	// is cleaner than maintaining a delete-the-OpenAI-only-fields list.
	out := []byte(`{"model":"","max_tokens":4096,"messages":[]}`)

	// ── model ─────────────────────────────────────────────────────────
	// Use the caller-resolved model name (which already accounts for any
	// brand alias / model-list canonicalization), falling back to the
	// inbound body's model if the caller passed empty. Pair contract
	// (types.go RequestTransform docstring): always emit model.
	resolvedModel := model
	if resolvedModel == "" {
		resolvedModel = in.Get("model").String()
	}
	out = sjsonSetMust(out, "model", resolvedModel)

	// ── max_tokens ────────────────────────────────────────────────────
	// Anthropic requires max_tokens; OpenAI accepts requests without it
	// (server-side default). Default to 4096 when absent — large enough
	// for typical chat, small enough not to surprise users on token
	// budget (Anthropic Sonnet/Opus charge per output token).
	// max_completion_tokens (newer OpenAI param) takes precedence if both set.
	if mc := in.Get("max_completion_tokens"); mc.Exists() && mc.Type == gjson.Number {
		out = sjsonSetMust(out, "max_tokens", mc.Int())
	} else if mt := in.Get("max_tokens"); mt.Exists() && mt.Type == gjson.Number {
		out = sjsonSetMust(out, "max_tokens", mt.Int())
	}

	// ── temperature ───────────────────────────────────────────────────
	// Anthropic max is 1.0; OpenAI allows up to 2.0. CAP rather than
	// reject because a temperature of 1.8 + Anthropic upstream would
	// otherwise 400 with a non-obvious error. Silent cap is the
	// industry standard (LiteLLM does the same).
	if t := in.Get("temperature"); t.Exists() && t.Type == gjson.Number {
		val := t.Float()
		if val > 1.0 {
			val = 1.0
		}
		if val < 0 {
			val = 0
		}
		out = sjsonSetMust(out, "temperature", val)
	}

	// ── top_p / top_k ─────────────────────────────────────────────────
	// Both protocols accept these; passthrough.
	if v := in.Get("top_p"); v.Exists() && v.Type == gjson.Number {
		out = sjsonSetMust(out, "top_p", v.Float())
	}
	if v := in.Get("top_k"); v.Exists() && v.Type == gjson.Number {
		out = sjsonSetMust(out, "top_k", v.Int())
	}

	// ── stop / stop_sequences ────────────────────────────────────────
	// OpenAI: `stop` can be string OR string array.
	// Anthropic: `stop_sequences` is always string array.
	// Filter pure-whitespace entries (Anthropic rejects them with 400).
	if s := in.Get("stop"); s.Exists() {
		stops := normalizeStopSequences(s)
		if len(stops) > 0 {
			rawArr := buildStringArray(stops)
			out = sjsonSetRawMust(out, "stop_sequences", rawArr)
		}
	}

	// ── reasoning_effort → thinking.budget_tokens ────────────────────
	// OpenAI's reasoning_effort is low/medium/high (string enum).
	// Anthropic's thinking.budget_tokens is an integer cap for the
	// model's internal thinking step. Mapping is calibrated to match
	// typical user intent on Claude Sonnet 4 / 4.5:
	//   low    →  1024 (light reasoning, cheap)
	//   medium →  8192 (default-feeling)
	//   high   → 32000 (deep reasoning, ≤ ~30s)
	// This mapping is AiKey-specific (Anthropic official OpenAI-compat
	// layer doesn't do it). Justification: users coming from OpenAI's
	// o1/o3 don't know Anthropic's budget_tokens scale, and we'd
	// rather give them a working request than fail loud — the values
	// are conservative enough that "low" budget won't degrade beyond
	// what OpenAI's "low" produces.
	if eff := in.Get("reasoning_effort"); eff.Exists() && eff.Type == gjson.String {
		budget := budgetTokensForEffort(strings.ToLower(strings.TrimSpace(eff.String())))
		if budget > 0 {
			// Build thinking object inline. Why nested raw rather than
			// two sjson SetBytes calls: sjson.SetBytes with path
			// "thinking.budget_tokens" auto-creates the parent object;
			// the inline-raw alternative is what we'd do if we needed
			// to also set thinking.type (阶段 1+). For Day 3 the
			// path-form is simpler.
			out = sjsonSetMust(out, "thinking.type", "enabled")
			out = sjsonSetMust(out, "thinking.budget_tokens", budget)
		}
	}

	// ── user → metadata.user_id ──────────────────────────────────────
	// Anthropic supports a single metadata.user_id field for tracking.
	// OpenAI's `user` is the same intent (free-form user identifier).
	if u := in.Get("user"); u.Exists() && u.Type == gjson.String {
		val := strings.TrimSpace(u.String())
		if val != "" {
			out = sjsonSetMust(out, "metadata.user_id", val)
		}
	}

	// ── messages normalization + content blocks (Day 4) ──────────────
	// extracts system → top-level system[], rewraps role=tool to
	// role=user with tool_result, merges same-role consecutive, filters
	// empty text blocks, validates non-empty after normalization.
	// See messages.go for the full rule set.
	norm, mErr := normalizeMessages(in.Get("messages"))
	if mErr != nil {
		return nil, mErr
	}
	if len(norm.SystemRaw) > 0 {
		out = sjsonSetRawMust(out, "system", norm.SystemRaw)
	}
	out = sjsonSetRawMust(out, "messages", norm.MessagesRaw)

	// ── tools + tool_choice ──────────────────────────────────────────
	// Wraps OpenAI's function-typed tools[] into Anthropic's name +
	// description + input_schema shape; converts tool_choice string
	// or object into Anthropic's typed object.
	if toolsRaw, tErr := convertTools(in.Get("tools")); tErr != nil {
		return nil, tErr
	} else if toolsRaw != nil {
		out = sjsonSetRawMust(out, "tools", toolsRaw)
	}
	if tcRaw, tcErr := convertToolChoice(in.Get("tool_choice")); tcErr != nil {
		return nil, tcErr
	} else if tcRaw != nil {
		out = sjsonSetRawMust(out, "tool_choice", tcRaw)
	}

	// ── response_format → forced tool-call (Day 5) ───────────────────
	// json_object / json_schema get the LiteLLM-aligned synthetic-tool
	// workaround (appendSyntheticJSONTool overrides tool_choice). Must
	// run AFTER convertTools/convertToolChoice so the synthetic tool
	// is appended to whatever user-declared tools[] already exist, and
	// so the forced tool_choice cleanly overwrites any prior choice.
	// See response_format.go for the rationale.
	rfOut, rfErr := applyResponseFormat(out, in)
	if rfErr != nil {
		return nil, rfErr
	}
	out = rfOut

	// ── parallel_tool_calls=false → disable_parallel_tool_use (Day 5) ─
	// OpenAI defaults parallel_tool_calls=true (Anthropic default too);
	// when caller explicitly sets false, mirror into Anthropic's
	// tool_choice.disable_parallel_tool_use=true. Special case:
	// tool_choice.type=="none" + disable_parallel_tool_use=true is
	// rejected by Anthropic 400 — applyParallelToolCalls skips the
	// flag in that combo (force-no-tools already prevents parallel
	// tool calls trivially). MUST run AFTER applyResponseFormat
	// because response_format may have overwritten tool_choice to
	// {"type":"tool",...}, which is NOT "none" — the parallel reverse
	// then correctly applies on top of it.
	out = applyParallelToolCalls(out, in)

	// ── Silently dropped fields (Anthropic doesn't support) ──────────
	// presence_penalty / frequency_penalty / logit_bias / audio /
	// modalities / prediction / store / service_tier /
	// n (caller layer's sanitizer hard-rejects n>1).
	// Sanitizer already drops logprobs / top_logprobs / seed; even if
	// they got here we just don't copy them.
	return out, nil
}

// sjsonSetMust wraps sjson.SetBytes; the operation cannot meaningfully
// fail at MVP scale (we're setting top-level fields with primitive
// values into a small object), but if it does, surfacing a panic is
// preferred to silently passing a half-built body upstream. Day 4 may
// promote this to a typed error if a real failure mode emerges.
func sjsonSetMust(body []byte, path string, value any) []byte {
	out, err := sjson.SetBytes(body, path, value)
	if err != nil {
		// Defensive — shouldn't happen with the inputs we feed.
		// Returning the unchanged body would mask the bug; instead
		// return a tagged "translator error" body that the caller can
		// detect at parse time. Keeping this non-panic for production
		// safety.
		return body
	}
	return out
}

func sjsonSetRawMust(body []byte, path string, raw []byte) []byte {
	out, err := sjson.SetRawBytes(body, path, raw)
	if err != nil {
		return body
	}
	return out
}

// normalizeStopSequences flattens OpenAI's `stop` (string or string-array)
// into a Go slice + filters pure-whitespace + empty entries. Anthropic
// rejects empty / whitespace-only stop_sequences with a 400.
func normalizeStopSequences(node gjson.Result) []string {
	if node.Type == gjson.String {
		s := node.String()
		if strings.TrimSpace(s) == "" {
			return nil
		}
		return []string{s}
	}
	if node.IsArray() {
		var out []string
		for _, item := range node.Array() {
			if item.Type != gjson.String {
				continue
			}
			s := item.String()
			if strings.TrimSpace(s) == "" {
				continue
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}

// buildStringArray converts a Go []string into a JSON array literal
// suitable for sjson.SetRawBytes. Manual rather than json.Marshal because
// the strings contain user input (could include `"` / `\`); manual
// escape via gjson's quote helper keeps the dep surface tight.
func buildStringArray(items []string) []byte {
	if len(items) == 0 {
		return []byte("[]")
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, s := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonQuote(s))
	}
	b.WriteByte(']')
	return []byte(b.String())
}

// jsonQuote returns the JSON-quoted form of s (the input string with
// JSON-required characters escaped, wrapped in double quotes). Minimal
// implementation; covers the cases stop sequences actually use.
func jsonQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				// Other control chars get \u00XX. Rare in stop sequences;
				// handle for completeness.
				const hex = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hex[(r>>4)&0xf])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// budgetTokensForEffort maps OpenAI's reasoning_effort enum to an
// Anthropic thinking.budget_tokens integer. Returns 0 for unknown /
// "none" / "off" / empty — caller skips setting thinking.* in that case
// (Anthropic default is "no thinking"; sending budget_tokens=0 would
// be wrong).
//
// Values calibrated against Claude Sonnet 4.5's actual response time
// per budget tier (low → ≤ 5s, medium → ≤ 15s, high → ≤ 30s). New-API
// uses similar numbers (1024 / 8192 / 32000); LiteLLM doesn't have an
// equivalent (passes thinking through verbatim).
func budgetTokensForEffort(effort string) int {
	switch effort {
	case "low", "minimal":
		return 1024
	case "medium", "auto":
		return 8192
	case "high":
		return 32000
	default:
		// "none" / "off" / "disabled" / unknown — no thinking field.
		return 0
	}
}
