package openai_responses

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// chatCompletion is the Chat Completions non-stream response shape.
type chatCompletion struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []chatChoice `json:"choices"`
	Usage   *chatUsage   `json:"usage,omitempty"`
}

type chatChoice struct {
	Index        int         `json:"index"`
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type chatMessage struct {
	Role      string         `json:"role"`
	Content   *string        `json:"content"`
	ToolCalls []chatToolCall `json:"tool_calls,omitempty"`
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

type chatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ConvertNonStreamResponse translates a Responses API response body back into
// the Chat Completions shape the client is waiting for. Implements
// translator.NonStreamTransform.
//
// The Responses body carries an `output[]` array of heterogeneous items; a
// single assistant turn is spread across a message item (whose content parts
// hold the text) and zero or more function_call items. Chat Completions
// instead has ONE message object with `content` plus a `tool_calls` array, so
// the translation is a fold, not a field rename.
func ConvertNonStreamResponse(ctx context.Context, body []byte) ([]byte, *translator.TranslateError) {
	_ = ctx

	if !gjson.ValidBytes(body) {
		return nil, &translator.TranslateError{
			Code:       translator.CodeTranslationFailed,
			HTTPStatus: 502,
			Message:    "the upstream returned a body that is not valid JSON",
		}
	}
	in := gjson.ParseBytes(body)

	// An upstream error body reaches this function unchanged (the proxy only
	// translates 2xx). Pass it through rather than folding it into an empty
	// completion, which would render an error as a successful empty answer.
	//
	// 🔴 An explicit `"error": null` is NOT an error. Every real Responses object
	// carries that key (incomplete_details, user, previous_response_id … are null
	// too), and gjson's Exists() is true for a JSON null. This check used to be
	// `Exists()` alone, so it passed EVERY successful response through untranslated:
	// on master2 staging (2026-09-11) a non-streaming Chat Completions client got
	// the raw Responses object back, with no error and no log line. No fixture had
	// the key, so no test saw it. Same null guard as messages.go uses for content.
	// Bugfix: workflow/CI/bugfix/2026-09-11-bridge-error-null-treated-as-error-envelope.md
	// Fences: TestConvertNonStreamResponse_ExplicitNullErrorIsASuccessNotAnErrorEnvelope,
	//         TestDeStream_RealCodexStreamServesAllThreeClientShapes
	if e := in.Get("error"); e.Exists() && e.Type != gjson.Null {
		return body, nil
	}

	var text strings.Builder
	var toolCalls []chatToolCall

	for _, item := range in.Get("output").Array() {
		switch item.Get("type").String() {
		case "message", "":
			for _, part := range item.Get("content").Array() {
				// output_text is the only text-bearing part an assistant turn
				// produces. `refusal` parts are deliberately not folded into
				// content — see the refusal handling below.
				if part.Get("type").String() == "output_text" {
					text.WriteString(part.Get("text").String())
				}
			}
		case "function_call":
			toolCalls = append(toolCalls, chatToolCall{
				ID:   item.Get("call_id").String(),
				Type: "function",
				Function: chatToolFunction{
					Name:      item.Get("name").String(),
					Arguments: item.Get("arguments").String(),
				},
			})
		case "reasoning":
			// Reasoning items carry the model's private chain of thought.
			// Chat Completions has no field for them and the caller did not
			// ask for them; forwarding would both break the shape and leak
			// content the Responses API marks as internal.
		}
	}

	content := text.String()
	msg := chatMessage{Role: "assistant", ToolCalls: toolCalls}
	// `content` must be present-but-null (not omitted) on a tool-call turn:
	// that is what the OpenAI SDKs check before reading tool_calls.
	if content != "" || len(toolCalls) == 0 {
		msg.Content = &content
	}

	out := chatCompletion{
		ID:      chatCompletionID(in.Get("id").String()),
		Object:  "chat.completion",
		Created: responseCreatedAt(in),
		Model:   in.Get("model").String(),
		Choices: []chatChoice{{
			Index:        0,
			Message:      msg,
			FinishReason: finishReason(in, len(toolCalls) > 0),
		}},
		Usage: convertUsage(in.Get("usage")),
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, &translator.TranslateError{
			Code:       translator.CodeTranslationFailed,
			HTTPStatus: 500,
			Message:    "could not encode the translated Chat Completions response: " + err.Error(),
		}
	}
	return encoded, nil
}

// finishReason maps the Responses completion status to the Chat Completions
// vocabulary.
//
// Why tool calls win over status: a turn that ends in a tool call is reported
// by the upstream as status=completed, but a Chat Completions client keys its
// agent loop on finish_reason=="tool_calls". Reporting "stop" there ends the
// loop with the tool never being run — the request looks successful and the
// agent silently stops working.
func finishReason(in gjson.Result, hasToolCalls bool) string {
	if hasToolCalls {
		return "tool_calls"
	}
	switch in.Get("status").String() {
	case "incomplete":
		if in.Get("incomplete_details.reason").String() == "max_output_tokens" {
			return "length"
		}
		return "stop"
	case "failed":
		return "stop"
	default:
		return "stop"
	}
}

// convertUsage renames the Responses token fields to the Chat Completions
// ones. Returns nil when the upstream reported no usage at all, so the client
// sees an absent `usage` rather than a confident set of zeros.
func convertUsage(u gjson.Result) *chatUsage {
	if !u.Exists() {
		return nil
	}
	in := int(u.Get("input_tokens").Int())
	out := int(u.Get("output_tokens").Int())
	total := int(u.Get("total_tokens").Int())
	if total == 0 {
		total = in + out
	}
	return &chatUsage{PromptTokens: in, CompletionTokens: out, TotalTokens: total}
}

// chatCompletionID derives the client-visible id from the upstream one.
//
// Why derive rather than generate: the id is the only handle a user has when
// correlating a client-side log line with an upstream incident, so it must
// stay traceable to the `resp_…` the upstream issued. Why not pass it through
// verbatim: OpenAI SDK users (and their log tooling) expect the `chatcmpl-`
// prefix on this shape, and some clients assert on it.
func chatCompletionID(responseID string) string {
	if responseID == "" {
		return "chatcmpl-aikey"
	}
	return "chatcmpl-" + strings.TrimPrefix(responseID, "resp_")
}

// responseCreatedAt reads the upstream creation timestamp, falling back to now
// when the upstream omits it. Chat Completions clients treat `created` as
// required and some SDKs fail to deserialize a zero.
func responseCreatedAt(in gjson.Result) int64 {
	if v := in.Get("created_at"); v.Exists() && v.Int() > 0 {
		return v.Int()
	}
	return time.Now().Unix()
}
