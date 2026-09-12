package openai_responses

import (
	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
)

// init registers the (openai → openai-responses) pair with the default
// Registry. Blank-imported by the proxy so the side effect fires at startup,
// before any request can dispatch.
//
// Only ONE direction is registered. That is not an omission: the pair's
// direction is named for the REQUEST leg, and the Registry swaps it internally
// for responses (see Registry.TranslateNonStream). A client speaking Responses
// to a Responses upstream needs no translation at all and must stay a
// byte-for-byte passthrough — registering (openai-responses → openai) would
// advertise a conversion nothing should ever ask for.
func init() {
	translator.DefaultRegistry().Register(
		translator.FormatOpenAI,
		translator.FormatOpenAIResponses,
		ConvertRequest,
		translator.ResponseTransforms{
			NonStream:   ConvertNonStreamResponse,
			Stream:      ConvertStreamChunk,
			StreamFlush: FlushStream,
		},
	)
}
