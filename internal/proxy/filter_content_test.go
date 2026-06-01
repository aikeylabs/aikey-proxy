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
