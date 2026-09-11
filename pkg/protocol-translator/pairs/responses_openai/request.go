package responses_openai

import (
	"context"
	"encoding/json"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// chatRequest is the Chat Completions request shape we emit.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`

	// MaxCompletionTokens, not the older max_tokens. OpenAI deprecated
	// max_tokens for chat completions and the reasoning-model families REJECT
	// it outright ("Unsupported parameter: 'max_tokens' is not supported with
	// this model. Use 'max_completion_tokens' instead") — and those are exactly
	// the models a Responses-speaking client is using, so the old spelling
	// would turn a working request into a hard 400.
	//
	// Confirmed against an independent implementation: Wei-Shaw/sub2api's
	// apicompat.ResponsesToChatCompletionsRequest emits the same field.
	MaxCompletionTokens *int       `json:"max_completion_tokens,omitempty"`
	Temperature         *float64   `json:"temperature,omitempty"`
	TopP                *float64   `json:"top_p,omitempty"`
	ParallelToolCalls   *bool      `json:"parallel_tool_calls,omitempty"`
	ReasoningEffort     string     `json:"reasoning_effort,omitempty"`
	Tools               []chatTool `json:"tools,omitempty"`
	ToolChoice          any        `json:"tool_choice,omitempty"`
	Stream              bool       `json:"stream,omitempty"`
}

// chatMessage is one Chat Completions message.
//
// Content is `any` rather than a string because the two legal shapes are not
// interchangeable at the upstream: a plain string is what every
// OpenAI-compatible relay accepts, while a parts array is required for images
// and is rejected by some older ones. See contentValue for which is emitted.
type chatMessage struct {
	Role       string         `json:"role"`
	Content    any            `json:"content"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type chatToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Index    *int             `json:"index,omitempty"`
	Function chatToolFunction `json:"function"`
}

type chatToolFunction struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments"`
}

// chatTool nests the schema under `function`, which is where Chat Completions
// looks for it — the mirror of the flattening the forward pair does.
type chatTool struct {
	Type     string       `json:"type"`
	Function chatToolDecl `json:"function"`
}

type chatToolDecl struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

// ConvertRequest transforms a Responses API request body into a Chat
// Completions request body. Implements translator.RequestTransform.
func ConvertRequest(ctx context.Context, model string, body []byte, stream bool) ([]byte, *translator.TranslateError) {
	_ = ctx

	if !gjson.ValidBytes(body) {
		return nil, &translator.TranslateError{
			Code:       translator.CodeBadRequest,
			HTTPStatus: 400,
			Message:    "request body is not valid JSON",
		}
	}
	in := gjson.ParseBytes(body)

	if tErr := rejectStatefulAndUnmappable(in); tErr != nil {
		return nil, tErr
	}

	resolvedModel := model
	if resolvedModel == "" {
		resolvedModel = in.Get("model").String()
	}

	messages, tErr := convertInput(in.Get("instructions"), in.Get("input"))
	if tErr != nil {
		return nil, tErr
	}

	out := chatRequest{
		Model:    resolvedModel,
		Messages: messages,
		Stream:   stream,
	}

	if v := in.Get("max_output_tokens"); v.Exists() {
		n := int(v.Int())
		out.MaxCompletionTokens = &n
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
	// reasoning.effort and reasoning_effort are the same knob spelled two ways;
	// this one genuinely maps, so it is carried rather than refused.
	if v := in.Get("reasoning.effort"); v.Exists() {
		out.ReasoningEffort = v.String()
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
			Message:    "could not encode the translated Chat Completions request: " + err.Error(),
		}
	}
	return encoded, nil
}

// rejectStatefulAndUnmappable refuses the Responses fields that a Chat
// Completions upstream cannot honor.
//
// The list is short and every entry earns its place by changing what comes
// back, invisibly:
//
//   - previous_response_id — the worst of them. Responses keeps the
//     conversation server-side; this field says "continue from that". A Chat
//     Completions upstream holds no history and cannot be told to fetch any, so
//     forwarding without it silently reduces the conversation to the current
//     turn. The request succeeds, the model answers fluently, and it answers
//     without the context the caller believed it had.
//
//   - include — asks for extra payload (log probs, reasoning content, file
//     search results) in the response. Dropping it returns a well-formed answer
//     missing the data the caller is about to read.
//
//   - truncation:"auto" — lets the server drop middle-of-conversation content
//     to fit the window. Chat Completions has no equivalent, so a request that
//     relied on it starts failing on long inputs instead of being truncated.
//
//   - text.format — structured output. Dropping it returns free-form prose to
//     a caller that is going to json.Unmarshal it.
//
// `store` is deliberately NOT here: it is a real Chat Completions field on
// current OpenAI, and where an upstream does not know it, it is ignored
// server-side rather than changing this turn's answer.
func rejectStatefulAndUnmappable(in gjson.Result) *translator.TranslateError {
	unsupported := func(param, why string) *translator.TranslateError {
		return &translator.TranslateError{
			Code:       translator.CodeUnsupportedParam,
			HTTPStatus: 400,
			Param:      param,
			Message: "`" + param + "` cannot be expressed against this credential's upstream, which " +
				"speaks the Chat Completions API. " + why,
		}
	}
	if v := in.Get("previous_response_id"); v.Exists() && v.String() != "" {
		return unsupported("previous_response_id",
			"That upstream keeps no server-side conversation, so the earlier turns it refers to "+
				"cannot be retrieved and the model would answer with only the current turn as context. "+
				"Send the full conversation in `input` instead.")
	}
	if v := in.Get("include"); v.Exists() && len(v.Array()) > 0 {
		return unsupported("include",
			"The extra payload it selects has no Chat Completions equivalent, so the response would "+
				"come back well-formed but without the data you asked to include.")
	}
	if v := in.Get("truncation"); v.Exists() && v.String() != "" && v.String() != "disabled" {
		return unsupported("truncation",
			"Server-side context truncation has no Chat Completions equivalent; a conversation that "+
				"relied on it would start failing on length instead of being truncated.")
	}
	if v := in.Get("text.format.type"); v.Exists() && v.String() != "" && v.String() != "text" {
		return unsupported("text.format",
			"Structured-output translation is not implemented, and forwarding without it would return "+
				"free-form prose where your client expects parseable JSON.")
	}
	return nil
}
