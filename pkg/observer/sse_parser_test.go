package observer

import (
	"bytes"
	"testing"
)

// Each test pins one wire-format invariant. The names follow the
// "Test<Subject>_<Behavior>" convention used by the registry tests.

func TestSSEParser_SingleCompleteFrame(t *testing.T) {
	p := NewSSEParser()
	frames := p.Parse([]byte("event: message\ndata: hello\n\n"))
	if len(frames) != 1 {
		t.Fatalf("want 1 frame, got %d: %#v", len(frames), frames)
	}
	if frames[0].EventType != "message" {
		t.Errorf("event = %q, want message", frames[0].EventType)
	}
	if string(frames[0].Data) != "hello" {
		t.Errorf("data = %q, want hello", string(frames[0].Data))
	}
}

func TestSSEParser_TwoFramesInOneChunk(t *testing.T) {
	p := NewSSEParser()
	frames := p.Parse([]byte("event: a\ndata: 1\n\nevent: b\ndata: 2\n\n"))
	if len(frames) != 2 {
		t.Fatalf("want 2 frames, got %d", len(frames))
	}
	if frames[0].EventType != "a" || string(frames[0].Data) != "1" {
		t.Errorf("frame 0 = (%q, %q), want (a, 1)", frames[0].EventType, string(frames[0].Data))
	}
	if frames[1].EventType != "b" || string(frames[1].Data) != "2" {
		t.Errorf("frame 1 = (%q, %q), want (b, 2)", frames[1].EventType, string(frames[1].Data))
	}
}

func TestSSEParser_PartialFrameStraddlesChunkBoundary(t *testing.T) {
	p := NewSSEParser()
	// Read 1: partial frame (no trailing blank line yet)
	frames1 := p.Parse([]byte("event: message\ndata: hel"))
	if len(frames1) != 0 {
		t.Fatalf("partial frame should yield 0 frames, got %d", len(frames1))
	}
	// Read 2: complete the frame + start a new one
	frames2 := p.Parse([]byte("lo\n\nevent: next\ndata: world\n\n"))
	if len(frames2) != 2 {
		t.Fatalf("want 2 frames, got %d", len(frames2))
	}
	if string(frames2[0].Data) != "hello" {
		t.Errorf("frame 0 data = %q, want hello (cross-chunk reassembly broke)", string(frames2[0].Data))
	}
	if string(frames2[1].Data) != "world" {
		t.Errorf("frame 1 data = %q, want world", string(frames2[1].Data))
	}
}

func TestSSEParser_CRLFLineEndings(t *testing.T) {
	p := NewSSEParser()
	frames := p.Parse([]byte("event: message\r\ndata: hello\r\n\r\n"))
	if len(frames) != 1 {
		t.Fatalf("want 1 frame for CRLF, got %d", len(frames))
	}
	if string(frames[0].Data) != "hello" {
		t.Errorf("CRLF data = %q, want hello", string(frames[0].Data))
	}
}

func TestSSEParser_MultilineData(t *testing.T) {
	// Per spec, multiple data: lines in the same frame concatenate with '\n'.
	p := NewSSEParser()
	frames := p.Parse([]byte("data: line1\ndata: line2\ndata: line3\n\n"))
	if len(frames) != 1 {
		t.Fatalf("want 1 frame, got %d", len(frames))
	}
	if string(frames[0].Data) != "line1\nline2\nline3" {
		t.Errorf("multiline data = %q, want line1\\nline2\\nline3", string(frames[0].Data))
	}
}

func TestSSEParser_CommentLinesDropped(t *testing.T) {
	p := NewSSEParser()
	frames := p.Parse([]byte(": keepalive\nevent: ping\ndata: ok\n: another comment\n\n"))
	if len(frames) != 1 {
		t.Fatalf("want 1 frame, got %d", len(frames))
	}
	if frames[0].EventType != "ping" || string(frames[0].Data) != "ok" {
		t.Errorf("comments leaked into output: event=%q data=%q", frames[0].EventType, string(frames[0].Data))
	}
}

func TestSSEParser_PureCommentFrameDropped(t *testing.T) {
	// A frame that is ONLY comments (e.g., heartbeat-only frame) emits no SSEFrame.
	p := NewSSEParser()
	frames := p.Parse([]byte(": keepalive\n: still alive\n\n"))
	if len(frames) != 0 {
		t.Fatalf("pure-comment frame should not emit, got %d frame(s)", len(frames))
	}
}

func TestSSEParser_LeadingSpaceStripped(t *testing.T) {
	// "data: foo" → value "foo" (one leading space stripped per spec)
	// "data:  foo" → value " foo" (only the first space is stripped)
	// "data:foo"  → value "foo" (no leading space at all)
	p := NewSSEParser()
	frames := p.Parse([]byte("data: one\n\ndata:  two\n\ndata:three\n\n"))
	if len(frames) != 3 {
		t.Fatalf("want 3 frames, got %d", len(frames))
	}
	if string(frames[0].Data) != "one" {
		t.Errorf("frame 0 = %q, want 'one' (one leading space stripped)", string(frames[0].Data))
	}
	if string(frames[1].Data) != " two" {
		t.Errorf("frame 1 = %q, want ' two' (only first space stripped)", string(frames[1].Data))
	}
	if string(frames[2].Data) != "three" {
		t.Errorf("frame 2 = %q, want 'three' (no space to strip)", string(frames[2].Data))
	}
}

func TestSSEParser_FieldNameOnlyLine(t *testing.T) {
	// "event" with no colon → value is empty per spec; we still record the field.
	p := NewSSEParser()
	frames := p.Parse([]byte("event\ndata: payload\n\n"))
	if len(frames) != 1 {
		t.Fatalf("want 1 frame, got %d", len(frames))
	}
	if frames[0].EventType != "" {
		t.Errorf("event = %q, want empty (field name only)", frames[0].EventType)
	}
}

func TestSSEParser_AnthropicShapeRealistic(t *testing.T) {
	// Realistic Anthropic stream snippet. degrade-detector's rhythm
	// observer keys off this exact frame shape. Each frame ends with
	// an explicit "\n\n" boundary — the trailing one matters because
	// without it the last frame stays buffered (correct per spec, but
	// would make this test see only 3 of 4 frames).
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"
	p := NewSSEParser()
	frames := p.Parse([]byte(stream))
	if len(frames) != 4 {
		t.Fatalf("want 4 frames, got %d", len(frames))
	}
	wantEvents := []string{"message_start", "content_block_delta", "content_block_delta", "message_stop"}
	for i, want := range wantEvents {
		if frames[i].EventType != want {
			t.Errorf("frame[%d].EventType = %q, want %q", i, frames[i].EventType, want)
		}
	}
	// Spot-check that the delta payload survived intact.
	if !bytes.Contains(frames[1].Data, []byte(`"text":"Hello"`)) {
		t.Errorf("frame[1].Data lost the delta text: %q", string(frames[1].Data))
	}
}

func TestSSEParser_ByteAtATimeIdenticalToBulk(t *testing.T) {
	// Feeding the same stream byte-by-byte must produce identical frames
	// to feeding it as one chunk. This is the strongest evidence that
	// partial-frame reassembly is correct under any read pattern.
	stream := []byte("event: a\ndata: 1\n\nevent: b\ndata: 22\n\nevent: c\ndata: 333\n\n")

	bulk := NewSSEParser()
	bulkFrames := bulk.Parse(stream)

	bytewise := NewSSEParser()
	var byteFrames []SSEFrame
	for i := 0; i < len(stream); i++ {
		byteFrames = append(byteFrames, bytewise.Parse(stream[i:i+1])...)
	}
	if len(bulkFrames) != len(byteFrames) {
		t.Fatalf("bulk got %d frames, bytewise got %d", len(bulkFrames), len(byteFrames))
	}
	for i := range bulkFrames {
		if bulkFrames[i].EventType != byteFrames[i].EventType {
			t.Errorf("frame[%d].EventType bulk=%q bytewise=%q", i, bulkFrames[i].EventType, byteFrames[i].EventType)
		}
		if !bytes.Equal(bulkFrames[i].Data, byteFrames[i].Data) {
			t.Errorf("frame[%d].Data bulk=%q bytewise=%q", i, string(bulkFrames[i].Data), string(byteFrames[i].Data))
		}
	}
}

func TestSSEParser_ResetDropsPartialFrame(t *testing.T) {
	p := NewSSEParser()
	p.Parse([]byte("event: a\ndata: hel")) // partial — buffered
	p.Reset()
	frames := p.Parse([]byte("event: b\ndata: x\n\n"))
	if len(frames) != 1 {
		t.Fatalf("after Reset, want 1 fresh frame, got %d", len(frames))
	}
	if frames[0].EventType != "b" || string(frames[0].Data) != "x" {
		t.Errorf("post-Reset frame leaked pre-Reset data: %#v", frames[0])
	}
}

func TestSSEParser_EmptyAndNilInputs(t *testing.T) {
	p := NewSSEParser()
	if got := p.Parse(nil); len(got) != 0 {
		t.Errorf("Parse(nil) returned %d frames, want 0", len(got))
	}
	if got := p.Parse([]byte{}); len(got) != 0 {
		t.Errorf("Parse([]byte{}) returned %d frames, want 0", len(got))
	}
}

func TestSSEParser_OnlyEventNoData(t *testing.T) {
	// A frame can validly carry an event type with no data (e.g.
	// Anthropic's `ping` event). Observers must still see EventType.
	p := NewSSEParser()
	frames := p.Parse([]byte("event: ping\n\n"))
	if len(frames) != 1 {
		t.Fatalf("want 1 frame, got %d", len(frames))
	}
	if frames[0].EventType != "ping" {
		t.Errorf("event = %q, want ping", frames[0].EventType)
	}
	if len(frames[0].Data) != 0 {
		t.Errorf("data = %q, want empty", string(frames[0].Data))
	}
}
