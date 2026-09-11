package openai_responses

import (
	"context"
	"encoding/json"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// responsesRequest is the Responses API request shape we emit.
//
// Why typed structs here while the openai_anthropic pair uses gjson/sjson:
// that pair performs SURGICAL edits on a handful of known top-level fields,
// which is what sjson is good at. This pair REBUILDS the body — `messages[]`
// becomes `instructions` plus a differently-shaped `input[]` whose items are
// polymorphic (message / function_call / function_call_output). Expressing
// that as a chain of sjson.SetRaw calls hides the resulting shape from the
// reader; a struct shows it. Marshal cost is ~single-digit µs on agent-sized
// bodies, far below the upstream round trip.
type responsesRequest struct {
	Model string `json:"model"`
	// Instructions is the Responses API's system-prompt slot. It carries the
	// concatenation of every system/developer message, in order.
	Instructions string        `json:"instructions,omitempty"`
	Input        []inputItem   `json:"input"`
	Tools        []responsTool `json:"tools,omitempty"`
	ToolChoice   any           `json:"tool_choice,omitempty"`
	// MaxOutputTokens is the Responses spelling of max_tokens.
	MaxOutputTokens   *int     `json:"max_output_tokens,omitempty"`
	Temperature       *float64 `json:"temperature,omitempty"`
	TopP              *float64 `json:"top_p,omitempty"`
	ParallelToolCalls *bool    `json:"parallel_tool_calls,omitempty"`
	Stream            bool     `json:"stream,omitempty"`
	// Store=false keeps the turn out of the ChatGPT account's server-side
	// conversation history. AiKey is a pass-through for someone else's
	// subscription; silently persisting their users' prompts into that
	// account's history would be a privacy decision we have no mandate to
	// make. Always emitted, never inherited from the client.
	Store bool `json:"store"`
}

// inputItem is one element of Responses `input[]`. The array is
// heterogeneous: plain conversation turns carry Role+Content, a model tool
// invocation carries Type=function_call, and a tool result carries
// Type=function_call_output. Fields are pointers/omitempty so each variant
// marshals to only its own keys.
type inputItem struct {
	Type    string        `json:"type,omitempty"`
	Role    string        `json:"role,omitempty"`
	Content []contentPart `json:"content,omitempty"`

	// function_call
	CallID    string `json:"call_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`

	// function_call_output
	Output string `json:"output,omitempty"`
}

// contentPart is one part of a message's content. The Responses API tags
// text differently depending on who said it: a user/system turn carries
// `input_text`, an assistant turn carries `output_text`. Sending the wrong
// tag is rejected upstream, so the mapping is by role, not by position.
type contentPart struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
}

// responsTool is the Responses API tool declaration. Chat Completions nests
// the schema under `function`; Responses flattens it.
type responsTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

// ConvertRequest transforms an OpenAI Chat Completions request body into a
// Responses API request body. Implements translator.RequestTransform.
//
// The `model` argument wins over the body's own `model` field (pair contract,
// types.go): the caller has already applied whatever alias / canonicalization
// the route demands, and re-reading the body would undo it.
func ConvertRequest(ctx context.Context, model string, body []byte, stream bool) ([]byte, *translator.TranslateError) {
	_ = ctx // no cancellable work: this is a bounded in-memory reshape

	if !gjson.ValidBytes(body) {
		return nil, &translator.TranslateError{
			Code:       translator.CodeBadRequest,
			HTTPStatus: 400,
			Message:    "request body is not valid JSON",
		}
	}
	in := gjson.ParseBytes(body)

	if tErr := rejectUnsupported(in); tErr != nil {
		return nil, tErr
	}

	resolvedModel := model
	if resolvedModel == "" {
		resolvedModel = in.Get("model").String()
	}

	out := responsesRequest{
		Model: resolvedModel,
		Input: []inputItem{},
		// The client's `stream` field is authoritative for the body, but the
		// caller's `stream` argument reflects what the transport actually
		// negotiated. They agree in every real path; prefer the argument so a
		// body/transport disagreement can't produce a half-streamed response.
		Stream: stream,
		Store:  false,
	}

	instructions, items, tErr := convertMessages(in.Get("messages"))
	if tErr != nil {
		return nil, tErr
	}
	out.Instructions = instructions
	out.Input = items

	// max_completion_tokens is the newer Chat Completions spelling; both map
	// to the same Responses field. Newer wins when a client sends both.
	if v := in.Get("max_completion_tokens"); v.Exists() {
		n := int(v.Int())
		out.MaxOutputTokens = &n
	} else if v := in.Get("max_tokens"); v.Exists() {
		n := int(v.Int())
		out.MaxOutputTokens = &n
	}
	if v := in.Get("temperature"); v.Exists() {
		f := v.Float()
		out.Temperature = &f
	}
	if v := in.Get("top_p"); v.Exists() {
		f := v.Float()
		out.TopP = &f
	}
	if v := in.Get("parallel_tool_calls"); v.Exists() {
		b := v.Bool()
		out.ParallelToolCalls = &b
	}

	tools, tErr := convertTools(in.Get("tools"))
	if tErr != nil {
		return nil, tErr
	}
	out.Tools = tools
	out.ToolChoice = convertToolChoice(in.Get("tool_choice"))

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, &translator.TranslateError{
			Code:       translator.CodeTranslationFailed,
			HTTPStatus: 500,
			Message:    "could not encode the translated Responses request: " + err.Error(),
		}
	}
	return encoded, nil
}

// rejectUnsupported fails loudly on Chat Completions parameters the Responses
// API cannot express.
//
// Why reject rather than drop: every field here CHANGES THE OUTPUT the caller
// receives. Dropping `stop` lets the model run past the caller's stop token;
// dropping `n` returns one choice where the caller indexed four; dropping a
// penalty changes the sampling distribution. All three produce a plausible
// answer that is quietly not the answer that was asked for — the failure mode
// CLAUDE.md 失败要显眼 exists to prevent. A 400 naming the parameter is
// recoverable in one edit; a silently different answer is not even detectable.
//
// Penalties are only rejected when non-zero: several SDKs serialize their
// zero-valued defaults, and refusing those would block callers who never
// asked for the behavior in the first place.
func rejectUnsupported(in gjson.Result) *translator.TranslateError {
	unsupported := func(param, why string) *translator.TranslateError {
		return &translator.TranslateError{
			Code:       translator.CodeUnsupportedParam,
			HTTPStatus: 400,
			Param:      param,
			Message: "`" + param + "` cannot be expressed against this credential's upstream. " + why +
				" Remove the parameter and re-issue the request.",
		}
	}
	if v := in.Get("n"); v.Exists() && v.Int() > 1 {
		return unsupported("n", "The upstream Responses API returns exactly one completion per request, "+
			"so a request for several would silently come back with one.")
	}
	if v := in.Get("stop"); v.Exists() && !isEmptyStop(v) {
		return unsupported("stop", "The upstream Responses API has no stop-sequence parameter, so the model "+
			"would keep generating past the sequence you specified.")
	}
	if v := in.Get("logprobs"); v.Exists() && v.Bool() {
		return unsupported("logprobs", "The upstream Responses API does not return token log-probabilities.")
	}
	for _, p := range []string{"frequency_penalty", "presence_penalty"} {
		if v := in.Get(p); v.Exists() && v.Float() != 0 {
			return unsupported(p, "The upstream Responses API has no equivalent sampling penalty, so the "+
				"output distribution would differ from what you configured.")
		}
	}
	if v := in.Get("response_format"); v.Exists() && v.Get("type").String() != "" &&
		v.Get("type").String() != "text" {
		return unsupported("response_format", "Structured-output translation to the Responses API's `text.format` "+
			"is not implemented yet, and forwarding the request without it would return free-form prose "+
			"where your client expects parseable JSON.")
	}
	return nil
}

// isEmptyStop reports whether a `stop` value carries no actual sequence.
// Clients serialize "unset" as null, "", or [] depending on the SDK, and none
// of those change behavior — only a real sequence does.
func isEmptyStop(v gjson.Result) bool {
	switch v.Type {
	case gjson.Null:
		return true
	case gjson.String:
		return v.String() == ""
	case gjson.JSON:
		if v.IsArray() {
			return len(v.Array()) == 0
		}
		return false
	case gjson.False, gjson.Number, gjson.True:
		return false
	default:
		return false
	}
}
