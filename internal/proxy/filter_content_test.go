package proxy

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// collect just the text values, sorted, for order-independent comparison.
func pieceTexts(pieces []contentPiece) []string {
	out := make([]string, len(pieces))
	for i, p := range pieces {
		out[i] = p.text
	}
	sort.Strings(out)
	return out
}

func TestExtractFilterableContent(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string // sorted expected texts; nil = ok but empty
		ok   bool
	}{
		{
			name: "anthropic_string_content_plus_system",
			body: `{"model":"claude","system":"be brief","messages":[{"role":"user","content":"hi there"}]}`,
			want: []string{"be brief", "hi there"},
			ok:   true,
		},
		{
			name: "content_block_array_text_only",
			body: `{"messages":[{"role":"user","content":[{"type":"text","text":"first"},{"type":"image","source":{}},{"type":"text","text":"second"}]}]}`,
			want: []string{"first", "second"},
			ok:   true,
		},
		{
			name: "openai_multi_message",
			body: `{"messages":[{"role":"system","content":"sys"},{"role":"user","content":"u1"},{"role":"assistant","content":"a1"}]}`,
			want: []string{"a1", "sys", "u1"},
			ok:   true,
		},
		{
			name: "system_as_block_array",
			body: `{"system":[{"type":"text","text":"sysblock"}],"messages":[{"role":"user","content":"q"}]}`,
			want: []string{"q", "sysblock"},
			ok:   true,
		},
		{
			name: "skips_empty_and_null_content",
			body: `{"messages":[{"role":"user","content":""},{"role":"assistant","content":null},{"role":"user","content":"real"}]}`,
			want: []string{"real"},
			ok:   true,
		},
		{
			name: "non_json_body",
			body: `not json at all`,
			want: nil,
			ok:   false,
		},
		{
			name: "json_without_messages",
			body: `{"model":"claude","max_tokens":64}`,
			want: nil,
			ok:   true, // valid object, just nothing to mask
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pieces, parsed, ok := extractFilterableContent([]byte(tc.body))
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			got := pieceTexts(pieces)
			if len(got) != len(tc.want) {
				t.Fatalf("texts = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("texts = %v, want %v", got, tc.want)
				}
			}
			if ok && parsed == nil {
				t.Error("parsed map should be non-nil when ok")
			}
		})
	}
}

// The setter must write back into the parsed structure so a re-marshal carries
// the masked content — for both string content and text blocks.
func TestContentPieceSetter_RoundTrips(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"secret 12345"},{"role":"user","content":[{"type":"text","text":"block 67890"}]}]}`
	pieces, parsed, ok := extractFilterableContent([]byte(body))
	if !ok || len(pieces) != 2 {
		t.Fatalf("expected 2 pieces, got %d (ok=%v)", len(pieces), ok)
	}
	for i := range pieces {
		pieces[i].setText("[REDACTED]")
	}
	out, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !json.Valid(out) {
		t.Fatalf("remarshal invalid: %s", s)
	}
	if s == body {
		t.Fatal("body unchanged after setText")
	}
	if !strings.Contains(s, "[REDACTED]") {
		t.Errorf("masked text not present after round-trip: %s", s)
	}
	for _, leak := range []string{"12345", "67890"} {
		if strings.Contains(s, leak) {
			t.Errorf("raw %q survived after setText round-trip: %s", leak, s)
		}
	}
}

// TestExtractUserContent_ResponsesAPI is the fence for the 2026-07-08 live
// incident: codex sends the OpenAI Responses API wire format (instructions +
// input[] with input_text content parts), which the filter extractor did NOT
// understand → "no filterable content extracted; forwarded UNFILTERED" → the
// sensitive word "fuck" reached the model unscanned while the SAME message was
// captured by the conversation audit (separate path, already Responses-aware).
// The compliance filter must scan the user turns of input[] too.
func TestExtractUserContent_ResponsesAPI(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
		ok   bool
	}{
		{
			name: "responses_input_item_array_scans_user_skips_instructions_and_assistant",
			body: `{"model":"gpt-5-codex","instructions":"be a coding agent","input":[
				{"type":"message","role":"user","content":[{"type":"input_text","text":"old turn"}]},
				{"type":"message","role":"assistant","content":[{"type":"output_text","text":"model reply"}]},
				{"type":"message","role":"user","content":[{"type":"input_text","text":"fuck"}]}
			]}`,
			// instructions (system-equivalent, admin) + assistant output must be
			// skipped; both user turns scanned.
			want: []string{"fuck", "old turn"},
			ok:   true,
		},
		{
			name: "responses_input_plain_string",
			body: `{"model":"gpt-5-codex","input":"fuck"}`,
			want: []string{"fuck"},
			ok:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pieces, parsed, ok := extractUserContent([]byte(tc.body))
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			got := pieceTexts(pieces)
			if len(got) != len(tc.want) {
				t.Fatalf("texts = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("texts = %v, want %v", got, tc.want)
				}
			}
			if ok && parsed == nil {
				t.Error("parsed nil when ok")
			}
		})
	}
}

// Mask write-back must round-trip through the Responses API input[] shape too,
// so re-marshaling yields the masked request the upstream receives.
func TestExtractUserContent_ResponsesAPI_MaskRoundTrip(t *testing.T) {
	body := `{"model":"gpt-5-codex","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"fuck"}]}]}`
	pieces, parsed, ok := extractUserContent([]byte(body))
	if !ok || len(pieces) != 1 {
		t.Fatalf("ok=%v pieces=%d, want ok + 1 piece", ok, len(pieces))
	}
	pieces[0].setText("****")
	out, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), `"****"`) || strings.Contains(string(out), "fuck") {
		t.Fatalf("mask not written back: %s", out)
	}
}
