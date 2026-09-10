package responses_openai

import (
	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
)

// init registers the (openai-responses → openai) pair with the default
// Registry — the reverse of the openai_responses pair, for a Responses-speaking
// client whose credential points at a Chat Completions upstream.
//
// EventName is supplied because the RESPONSE side of this pair emits Responses
// frames, and that dialect names its SSE events. The forward pair leaves it nil:
// its response side emits Chat Completions, which does not.
func init() {
	translator.DefaultRegistry().Register(
		translator.FormatOpenAIResponses,
		translator.FormatOpenAI,
		ConvertRequest,
		translator.ResponseTransforms{
			NonStream: ConvertNonStreamResponse,
			Stream:    ConvertStreamChunk,
			EventName: SSEEventName,
		},
	)
}
