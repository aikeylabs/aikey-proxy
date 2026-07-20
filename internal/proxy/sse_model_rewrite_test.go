package proxy

import (
	"io"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// P3.3: the SSE model rewriter restores message.model in the first
// message_start event and passes everything else through byte-for-byte.
func TestSSEModelRewriter(t *testing.T) {
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"m1","model":"glm-4.6","content":[]}}` + "\n" +
		"\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","delta":{"text":"hi"}}` + "\n" +
		"\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}` + "\n"

	rc := newSSEModelRewriter(io.NopCloser(strings.NewReader(stream)), "claude-opus-4-8")
	out, _ := io.ReadAll(rc)
	s := string(out)

	// first message_start model rewritten
	lines := strings.Split(s, "\n")
	var msgStartData string
	for _, ln := range lines {
		if strings.HasPrefix(ln, "data: ") && strings.Contains(ln, "message_start") {
			msgStartData = strings.TrimPrefix(ln, "data: ")
		}
	}
	if got := gjson.Get(msgStartData, "message.model").String(); got != "claude-opus-4-8" {
		t.Errorf("message_start model = %q, want claude-opus-4-8", got)
	}
	// delta text preserved (pass-through)
	if !strings.Contains(s, `"text":"hi"`) {
		t.Errorf("content delta lost: %s", s)
	}
	// event: lines preserved
	if !strings.Contains(s, "event: message_start") || !strings.Contains(s, "event: content_block_delta") {
		t.Errorf("event lines not preserved")
	}
	// glm-4.6 no longer present anywhere (only the one model field existed)
	if strings.Contains(s, "glm-4.6") {
		t.Errorf("upstream model name leaked to client: %s", s)
	}
}

// empty clientModel → pass-through wrapper (no allocation, identical bytes)
func TestSSEModelRewriter_NoMappingPassthrough(t *testing.T) {
	stream := `data: {"type":"message_start","message":{"model":"glm-4.6"}}` + "\n"
	rc := newSSEModelRewriter(io.NopCloser(strings.NewReader(stream)), "")
	out, _ := io.ReadAll(rc)
	if string(out) != stream {
		t.Errorf("no-mapping must pass through unchanged")
	}
}
