package responses_openai

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// responsesResponse is the Responses API response shape we emit.
type responsesResponse struct {
	ID        string       `json:"id"`
	Object    string       `json:"object"`
	CreatedAt int64        `json:"created_at"`
	Model     string       `json:"model"`
	Status    string       `json:"status"`
	Output    []outputItem `json:"output"`
	// OutputText is the flattened convenience field the official SDKs expose as
	// `response.output_text`. It is derived, not authoritative — but a client
	// that reads only that field would see an empty answer if we omitted it.
	OutputText        string             `json:"output_text"`
	IncompleteDetails *incompleteDetails `json:"incomplete_details,omitempty"`
	Usage             *responsesUsage    `json:"usage,omitempty"`
}

type incompleteDetails struct {
	Reason string `json:"reason"`
}

type outputItem struct {
	Type    string        `json:"type"`
	ID      string        `json:"id,omitempty"`
	Status  string        `json:"status,omitempty"`
	Role    string        `json:"role,omitempty"`
	Content []contentPart `json:"content,omitempty"`

	// function_call
	CallID    string `json:"call_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type contentPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
	// Annotations is always emitted (as []) because the SDKs type it as a
	// required list and a null there deserializes into a nil slice that some
	// versions then range over.
	Annotations []any `json:"annotations"`
}

type responsesUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// ConvertNonStreamResponse translates a Chat Completions response body back
// into the Responses shape. Implements translator.NonStreamTransform.
//
// The fold runs the other way from the forward pair: one Chat Completions
// message carrying content plus a tool_calls array becomes SEVERAL Responses
// output items — a message item for the prose and one function_call item per
// call, in that order.
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

	// An upstream error body is passed through unchanged; folding it into an
	// empty response would render a failure as a successful blank answer.
	if in.Get("error").Exists() {
		return body, nil
	}

	choice := in.Get("choices.0")
	msg := choice.Get("message")
	respID := responseID(in.Get("id").String())

	var out []outputItem
	text := msg.Get("content").String()
	if text != "" {
		out = append(out, outputItem{
			Type:    "message",
			ID:      "msg_" + strings.TrimPrefix(respID, "resp_"),
			Status:  "completed",
			Role:    "assistant",
			Content: []contentPart{{Type: "output_text", Text: text, Annotations: []any{}}},
		})
	}
	for i, tc := range msg.Get("tool_calls").Array() {
		out = append(out, outputItem{
			Type:      "function_call",
			ID:        functionCallItemID(respID, i),
			Status:    "completed",
			CallID:    tc.Get("id").String(),
			Name:      tc.Get("function.name").String(),
			Arguments: tc.Get("function.arguments").String(),
		})
	}
	if out == nil {
		out = []outputItem{}
	}

	status, incomplete := statusFor(choice.Get("finish_reason").String())

	encoded, err := json.Marshal(responsesResponse{
		ID:                respID,
		Object:            "response",
		CreatedAt:         createdAt(in),
		Model:             in.Get("model").String(),
		Status:            status,
		Output:            out,
		OutputText:        text,
		IncompleteDetails: incomplete,
		Usage:             convertUsage(in.Get("usage")),
	})
	if err != nil {
		return nil, &translator.TranslateError{
			Code:       translator.CodeTranslationFailed,
			HTTPStatus: 500,
			Message:    "could not encode the translated Responses response: " + err.Error(),
		}
	}
	return encoded, nil
}

// statusFor maps the Chat Completions finish_reason onto the Responses status
// pair (status + incomplete_details).
//
// `length` is the one that carries information a caller acts on: it means the
// answer was cut off. Responses expresses that as status=incomplete with a
// reason, and a client that only reads `status` would otherwise treat a
// truncated answer as a finished one.
//
// `tool_calls` maps to completed — in Responses a turn that ends in a tool call
// IS completed, and the caller detects the call by finding a function_call item
// in output[], not by reading the status.
func statusFor(finishReason string) (string, *incompleteDetails) {
	switch finishReason {
	case "length":
		return "incomplete", &incompleteDetails{Reason: "max_output_tokens"}
	case "content_filter":
		return "incomplete", &incompleteDetails{Reason: "content_filter"}
	default:
		return "completed", nil
	}
}

func convertUsage(u gjson.Result) *responsesUsage {
	if !u.Exists() {
		return nil
	}
	in := int(u.Get("prompt_tokens").Int())
	out := int(u.Get("completion_tokens").Int())
	total := int(u.Get("total_tokens").Int())
	if total == 0 {
		total = in + out
	}
	return &responsesUsage{InputTokens: in, OutputTokens: out, TotalTokens: total}
}

// responseID derives the Responses id from the Chat Completions one, mirroring
// the forward pair so a round trip through both keeps the same suffix and stays
// traceable to whatever the upstream actually issued.
func responseID(chatID string) string {
	if chatID == "" {
		return "resp_aikey"
	}
	return "resp_" + strings.TrimPrefix(chatID, "chatcmpl-")
}

// functionCallItemID gives each function_call item a stable id. Responses
// clients correlate streamed argument deltas by ITEM id (distinct from call_id,
// which correlates the eventual tool result), so the two must not be conflated.
func functionCallItemID(respID string, index int) string {
	return "fc_" + strings.TrimPrefix(respID, "resp_") + "_" + itoa(index)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func createdAt(in gjson.Result) int64 {
	if v := in.Get("created"); v.Exists() && v.Int() > 0 {
		return v.Int()
	}
	return time.Now().Unix()
}
