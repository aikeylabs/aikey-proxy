package provider

import (
	"bytes"
	"encoding/json"
)

// Incremental ("parse-and-discard") token extraction for streaming responses —
// the gap7 fix (workflow/CI/e2e/chaos/gap7-streaming-buffer-fix-proposal.md).
//
// Problem: stream_drainer accumulated the WHOLE SSE body into a bytes.Buffer
// (≈2× body size per concurrent stream, GB-scale at Cluster) only to run the
// whole-body ExtractTokenBreakdown once at stream end. StreamAccumulator lets the
// drainer feed frames AS THEY ARRIVE and keep only the running TokenBreakdown
// (a few ints + 2 strings) — memory becomes O(one frame) instead of O(body).
//
// Equivalence is GUARANTEED by tokenstream_fence_test.go: feeding the
// accumulator frame-by-frame must produce byte-identical TokenBreakdown to the
// existing whole-body ExtractTokenBreakdown for every fixture. The existing
// extractors are intentionally left UNTOUCHED (zero billing regression risk);
// the fence binds the two so they cannot drift.

// StreamAccumulator consumes one SSE frame's data payload at a time and yields
// the running token breakdown. Feed receives the JSON value of a `data:` frame
// (the "data:" prefix already stripped); non-`{` payloads (events, [DONE],
// heartbeats) are ignored. Result() returns the breakdown so far and may apply
// end-of-stream finalization (e.g. pure-input = raw-input − cached). NOT safe
// for concurrent use; one instance per stream.
type StreamAccumulator interface {
	Feed(frameData []byte)
	Result() TokenBreakdown
}

// StreamAccumulatorFactory is the OPTIONAL interface a Provider implements to
// offer incremental extraction. The drainer type-asserts it: providers that
// implement it get the low-memory path; any other (mock / future) provider
// safely falls back to whole-body accumulation. Non-breaking by construction.
type StreamAccumulatorFactory interface {
	NewStreamAccumulator() StreamAccumulator
}

// ---- Anthropic ----

// anthropicStreamAcc mirrors the per-line fold in Anthropic.ExtractTokenBreakdown
// exactly: message_start sets input/cache/model, message_delta sets output/stop;
// last write wins (each event type appears once in practice). Input is already
// the PURE uncached value (方案 A) — cache lives in its own fields.
type anthropicStreamAcc struct{ br TokenBreakdown }

func (a *Anthropic) NewStreamAccumulator() StreamAccumulator { return &anthropicStreamAcc{} }

func (s *anthropicStreamAcc) Feed(frameData []byte) {
	if len(frameData) == 0 || frameData[0] != '{' {
		return
	}
	var event struct {
		Type    string `json:"type"`
		Message struct {
			Model string         `json:"model"`
			Usage anthropicUsage `json:"usage"`
		} `json:"message"`
		Delta struct {
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
		Usage anthropicUsage `json:"usage"`
	}
	if json.Unmarshal(frameData, &event) != nil {
		return
	}
	switch event.Type {
	case "message_start":
		u := event.Message.Usage
		s.br.InputTokens = u.InputTokens
		s.br.CacheReadInputTokens = u.CacheReadInputTokens
		s.br.CacheCreationInputTokens = u.CacheCreationInputTokens
		if event.Message.Model != "" {
			s.br.Model = event.Message.Model
		}
	case "message_delta":
		s.br.OutputTokens = event.Usage.OutputTokens
		if event.Delta.StopReason != "" {
			s.br.StopReason = event.Delta.StopReason
		}
	}
}

func (s *anthropicStreamAcc) Result() TokenBreakdown { return s.br }

// ---- OpenAI (Kimi / Generic delegate) ----

// openaiStreamAcc replicates the EXACT per-field semantics of the five whole-body
// OpenAI scans, folded into one pass:
//   - in/out:    FIRST usage frame wins      (ExtractTokens returns on first Usage!=nil)
//   - cached:    LAST  non-zero wins         (extractOpenAICachedInput keeps last>0)
//   - reasoning: LAST  non-zero wins         (extractOpenAIReasoning keeps last>0)
//   - model:     FIRST non-empty wins        (extractOpenAIModel returns first)
//   - stop:      LAST  non-empty wins        (extractOpenAIStopReason keeps last)
//   - InputTokens (pure) = first-frame raw input − last-frame cached  (clamped ≥0)
// The first/last split is preserved verbatim so the fence is byte-identical even
// on pathological multi-usage-frame streams, not just the single-usage realistic case.
type openaiStreamAcc struct {
	br        TokenBreakdown
	rawInput  int
	inOutSeen bool
	modelSeen bool
}

func (o *OpenAI) NewStreamAccumulator() StreamAccumulator { return &openaiStreamAcc{} }
func (k *Kimi) NewStreamAccumulator() StreamAccumulator    { return (&OpenAI{}).NewStreamAccumulator() }
func (g *Generic) NewStreamAccumulator() StreamAccumulator { return (&OpenAI{}).NewStreamAccumulator() }

func (s *openaiStreamAcc) Feed(frameData []byte) {
	if len(frameData) == 0 || frameData[0] != '{' {
		return
	}
	var f struct {
		Model   string `json:"model"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage    *openaiUsageData `json:"usage"`
		Response *struct {
			Usage *openaiUsageData `json:"usage"`
		} `json:"response"`
	}
	if json.Unmarshal(frameData, &f) != nil {
		return
	}
	// model: first non-empty wins
	if !s.modelSeen && f.Model != "" {
		s.br.Model = f.Model
		s.modelSeen = true
	}
	// stop: last non-empty wins
	if len(f.Choices) > 0 && f.Choices[0].FinishReason != "" {
		s.br.StopReason = f.Choices[0].FinishReason
	}
	usage := f.Usage
	if usage == nil && f.Response != nil {
		usage = f.Response.Usage
	}
	if usage != nil {
		if !s.inOutSeen { // in/out: first usage frame wins
			in, out := usage.Resolve()
			s.rawInput = in
			s.br.OutputTokens = out
			s.inOutSeen = true
		}
		if c := usage.CachedInput(); c > 0 { // cached: last>0 wins
			s.br.CacheReadInputTokens = c
		}
		if r := usage.ReasoningTokens(); r > 0 { // reasoning: last>0 wins
			s.br.ReasoningTokens = r
		}
	}
}

func (s *openaiStreamAcc) Result() TokenBreakdown {
	pure := s.rawInput - s.br.CacheReadInputTokens
	if pure < 0 {
		pure = 0 // defensive: cached should never exceed prompt
	}
	s.br.InputTokens = pure
	return s.br
}

// feedStreamLine strips the SSE "data:" prefix (space-optional per spec) the same
// way the whole-body extractors do, then feeds the payload. Shared by the fence
// and any whole-body-equivalent driver. The drainer instead feeds frames from
// observer.SSEParser, which performs the equivalent strip.
func feedStreamLine(acc StreamAccumulator, rawLine []byte) {
	line := bytes.TrimSpace(rawLine)
	line = bytes.TrimPrefix(line, []byte("data: "))
	line = bytes.TrimPrefix(line, []byte("data:"))
	acc.Feed(line)
}
