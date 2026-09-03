package conversation_audit

// toolcalls.go — extracting the tool calls a model requested in one turn
// (阶段8 P13 leg A, tasks 13.1 / 13.2 / 13.6).
//
// # The gap this closes
//
// A turn that used tools reads, in the audit, like the model went silent
// halfway through: extract.go's joinContent has always skipped tool_use blocks
// and the streaming path only ever recognised text deltas. So "who touched my
// production database" broke at the FIRST hop — an administrator could see what
// the user asked and what the model said, and not what the model called in
// between.
//
// 🔴 This is a conversation-audit gap, not an MCP gateway feature. It stands on
// its own and ships on its own: proposal.md's whole argument for splitting the
// package out is that leg A has no prerequisite. Nothing here imports the MCP
// gateway.
//
// # 🔴 One traversal, not two
//
// The frame parse is shared with assistant-text extraction (extractFrame in
// extract.go). Adding a second Unmarshal per SSE frame would have doubled the
// per-frame cost of the hot path for a feature that is off for most turns, and
// it would have created a second place where "what does this frame mean"
// is decided — the exact split the parse-once philosophy exists to avoid.
//
// # 🔴 Arguments are SUMMARISED, and the gate is not ours
//
// Tool arguments are SQL, file contents, internal hostnames and sometimes
// credentials. R16: their retention granularity follows the MCP RAW-ARGUMENTS
// switch, NOT the conversation-audit switch, because it is the same data R6
// already ruled defaults to a summary. One piece of data behind two gates is
// the same as no gate.
//
// Leg A ships BEFORE that switch exists. 🔴 The fail-safe direction is therefore
// written into this file rather than left to a caller: ArgsRaw is never
// populated here, at all. Read the gate, cannot read it ⇒ the gate is shut.
// See rawArgumentsAreNeverCapturedHere below.
//
// spec: roadmap20260320/技术实现/阶段8-平台化/对话审计工具调用可见/proposal.md
//       R-conversation-tool-visibility-1 / -4

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// toolFrameKind is what one SSE frame said about tool calls.
type toolFrameKind int

const (
	// toolFrameNone — this frame carries no tool-call signal. The overwhelming
	// majority.
	toolFrameNone toolFrameKind = iota
	// toolFrameStart — a tool call began and we read its name.
	toolFrameStart
	// toolFrameArgs — argument bytes for an in-flight call.
	toolFrameArgs
	// toolFrameUnnamed — 🔴 the frame announced a tool call and we could NOT
	// read its name. Task 13.6: this must WARN, never be silently treated as
	// "this turn had no tool calls". The two are opposite facts, and the second
	// one is what an auditor would act on.
	toolFrameUnnamed
)

// toolFrame is one frame's tool-call signal.
type toolFrame struct {
	kind toolFrameKind
	// key identifies WHICH call within the turn. Protocols index their
	// concurrent tool calls differently (Anthropic by content-block index,
	// OpenAI by tool-call index, the Responses API by output index), so the key
	// is stringified per protocol rather than assumed to be an int.
	key  string
	id   string
	name string
	// args is either an increment (kind == toolFrameArgs) or the whole
	// arguments object when the protocol delivers it in one piece.
	args string
}

// toolCallAcc accumulates a turn's tool calls across frames.
//
// 🔴 Insertion-ordered. "The model asked for A then B" is a fact an auditor
// reads, and a map's iteration order would reorder it differently on every
// render — which reads as the record changing under them.
type toolCallAcc struct {
	order []string
	byKey map[string]*pendingToolCall
	// unnamed counts frames that announced a call whose name we could not read.
	// Surfaced so OnRequestEnd can WARN with a number rather than a boolean.
	unnamed int
}

type pendingToolCall struct {
	id   string
	name string
	args strings.Builder
}

func newToolCallAcc() *toolCallAcc {
	return &toolCallAcc{byKey: map[string]*pendingToolCall{}}
}

// observe folds one frame's signal into the accumulator.
func (a *toolCallAcc) observe(f toolFrame) {
	switch f.kind {
	case toolFrameUnnamed:
		a.unnamed++
	case toolFrameStart:
		p, ok := a.byKey[f.key]
		if !ok {
			p = &pendingToolCall{}
			a.byKey[f.key] = p
			a.order = append(a.order, f.key)
		}
		// 🔴 First non-empty wins for both fields. Some formats repeat the id on
		// every argument chunk and some send the name only once; overwriting
		// with a later empty value would blank a name we already had.
		if p.name == "" {
			p.name = f.name
		}
		if p.id == "" {
			p.id = f.id
		}
		if f.args != "" {
			p.args.WriteString(f.args)
		}
	case toolFrameArgs:
		p, ok := a.byKey[f.key]
		if !ok {
			// Arguments before a start frame. Kept rather than dropped: the
			// name may still arrive, and a call with arguments and no name is
			// more useful to an auditor than nothing — it becomes an unnamed
			// entry below, which is a visible state.
			p = &pendingToolCall{}
			a.byKey[f.key] = p
			a.order = append(a.order, f.key)
		}
		p.args.WriteString(f.args)
	case toolFrameNone:
	}
}

// result renders the accumulated calls in request order.
//
// 🔴 ArgsRaw is never set. See the file header: the gate that would permit raw
// arguments does not exist yet, and "the gate cannot be read" resolves to
// CLOSED, not to open. A fence asserts this file cannot populate it.
//
// 🔴 Returns an EMPTY, NON-NIL slice when the turn called nothing — never nil.
// That is the whole of task 13.8: on the wire, `[]` says "a proxy that captures
// tool calls looked, and there were none", while an ABSENT field says "the node
// that captured this turn does not collect them". Collapsing the first into the
// second would tell an administrator nothing happened when the truth is nobody
// looked, which is a false report, not a missing feature.
func (a *toolCallAcc) result() []mcpwire.TurnToolCall {
	out := make([]mcpwire.TurnToolCall, 0, len(a.order))
	for _, key := range a.order {
		p := a.byKey[key]
		out = append(out, mcpwire.TurnToolCall{
			ToolCallID: p.id,
			ToolName:   p.name,
			ArgsDigest: mcpwire.DigestArgs(json.RawMessage(p.args.String())),
			// 🔴 Leg A captures the model's REQUEST. Whether the call actually
			// went through the gateway is leg B's question, and until it is
			// answered every entry is `pending` — the honest value. Writing
			// `linked` here would claim a join nobody performed.
			LinkState: mcpwire.LinkStatePending,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// per-protocol frame readers
// ---------------------------------------------------------------------------
//
// 🔴 NONE of these shapes came from a live capture in this repository. They are
// written from the published wire formats, and the live-stack acceptance
// (tasks 13.A1–13.A4) is what would confirm them against a real client. Stated
// here rather than in a report, because the person who breaks one of these will
// be reading this file.

// anthropicToolFrame reads Anthropic's streaming tool_use blocks.
//
//	content_block_start  {"index":1,"content_block":{"type":"tool_use","id":…,"name":…}}
//	content_block_delta  {"index":1,"delta":{"type":"input_json_delta","partial_json":"…"}}
//
// The block INDEX is the key: a turn may open several tool_use blocks and their
// argument deltas interleave.
func anthropicToolFrame(f *anthropicFrame) toolFrame {
	switch f.Type {
	case "content_block_start":
		if f.ContentBlock.Type != "tool_use" {
			return toolFrame{}
		}
		if f.ContentBlock.Name == "" {
			// 🔴 A tool_use block with no name. Reported, not swallowed.
			return toolFrame{kind: toolFrameUnnamed, key: strconv.Itoa(f.Index)}
		}
		return toolFrame{
			kind: toolFrameStart, key: strconv.Itoa(f.Index),
			id: f.ContentBlock.ID, name: f.ContentBlock.Name,
		}
	case "content_block_delta":
		if f.Delta.Type != "input_json_delta" || f.Delta.PartialJSON == "" {
			return toolFrame{}
		}
		return toolFrame{kind: toolFrameArgs, key: strconv.Itoa(f.Index), args: f.Delta.PartialJSON}
	}
	return toolFrame{}
}

// openAIChatToolFrames returns EVERY tool-call entry in one frame.
//
// 🔴 Chat Completions may carry several tool_calls entries in a single delta
// when the model opens more than one call at once. Reading only the first would
// silently lose the others — and "the model called two tools, we recorded one"
// is precisely the miscount this whole feature exists to prevent.
func openAIChatToolFrames(payload []byte) []toolFrame {
	var f struct {
		Choices []struct {
			Delta struct {
				ToolCalls []struct {
					Index    int    `json:"index"`
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if json.Unmarshal(payload, &f) != nil || len(f.Choices) == 0 {
		return nil
	}
	var out []toolFrame
	for _, tc := range f.Choices[0].Delta.ToolCalls {
		key := strconv.Itoa(tc.Index)
		switch {
		case tc.Function.Name != "" || tc.ID != "":
			out = append(out, toolFrame{kind: toolFrameStart, key: key, id: tc.ID,
				name: tc.Function.Name, args: tc.Function.Arguments})
		case tc.Function.Arguments != "":
			out = append(out, toolFrame{kind: toolFrameArgs, key: key, args: tc.Function.Arguments})
		}
	}
	return out
}

// openAIResponsesToolFrame reads the Responses API's function-call events —
// the wire format Codex speaks (wire_api="responses"), which the existing
// openaiWireFormats table already had to learn the hard way for plain text.
//
//	{"type":"response.output_item.added","output_index":0,
//	 "item":{"type":"function_call","call_id":"call_…","name":"…"}}
//	{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"a\":"}
func openAIResponsesToolFrame(payload []byte) toolFrame {
	var f struct {
		Type        string `json:"type"`
		OutputIndex int    `json:"output_index"`
		Delta       string `json:"delta"`
		Item        struct {
			Type   string `json:"type"`
			ID     string `json:"id"`
			CallID string `json:"call_id"`
			Name   string `json:"name"`
		} `json:"item"`
	}
	if json.Unmarshal(payload, &f) != nil {
		return toolFrame{}
	}
	key := strconv.Itoa(f.OutputIndex)
	switch f.Type {
	case "response.output_item.added":
		if f.Item.Type != "function_call" {
			return toolFrame{}
		}
		if f.Item.Name == "" {
			return toolFrame{kind: toolFrameUnnamed, key: key}
		}
		id := f.Item.CallID
		if id == "" {
			id = f.Item.ID
		}
		return toolFrame{kind: toolFrameStart, key: key, id: id, name: f.Item.Name}
	case "response.function_call_arguments.delta":
		if f.Delta == "" {
			return toolFrame{}
		}
		return toolFrame{kind: toolFrameArgs, key: key, args: f.Delta}
	}
	return toolFrame{}
}

// geminiToolFrames reads Gemini's functionCall parts.
//
//	{"candidates":[{"content":{"parts":[{"functionCall":{"name":"…","args":{…}}}]}}]}
//
// 🔴 Gemini delivers the whole arguments object in one part rather than
// streaming it, so there is no accumulation — and no stable index either, so
// the key is the position within the turn. Several calls can arrive in ONE
// frame, which is why this returns a slice.
func geminiToolFrames(payload []byte, seen int) []toolFrame {
	var f struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					FunctionCall *struct {
						Name string          `json:"name"`
						Args json.RawMessage `json:"args"`
					} `json:"functionCall"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if json.Unmarshal(payload, &f) != nil || len(f.Candidates) == 0 {
		return nil
	}
	var out []toolFrame
	for _, p := range f.Candidates[0].Content.Parts {
		if p.FunctionCall == nil {
			continue
		}
		key := "g" + strconv.Itoa(seen+len(out))
		if p.FunctionCall.Name == "" {
			out = append(out, toolFrame{kind: toolFrameUnnamed, key: key})
			continue
		}
		out = append(out, toolFrame{
			kind: toolFrameStart, key: key,
			name: p.FunctionCall.Name, args: string(p.FunctionCall.Args),
		})
	}
	return out
}
