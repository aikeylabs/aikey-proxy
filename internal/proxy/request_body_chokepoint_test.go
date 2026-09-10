package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestSetRequestBody_GetBodyReplaysTheNewBytes is the fence for a failure mode
// that reports nothing anywhere.
//
// net/http replays GetBody when it retries — an HTTP/2 GOAWAY or
// REFUSED_STREAM, which the group lane deliberately makes retryable
// (group_serve.go, bugfix 2026-09-03). GetBody there points at the ORIGINAL
// buffered request, so a site that rewrote the body and left GetBody alone was
// arranging for the retry to send the PRE-rewrite bytes:
//
//   - the compliance filter's mask write-back → the retry carries the UNMASKED
//     prompt upstream, i.e. a transport-level retry defeats DLP;
//   - stream_options.include_usage → the retry reports no usage, so the request
//     is served and not billed;
//   - model mapping → the retry asks for the client's model, not the route's.
//
// None of those surface as an error. Keeping Body, ContentLength and GetBody in
// one function is what makes "I rewrote the body" and "the retry sends what I
// wrote" the same statement — this test is what keeps them there.
func TestSetRequestBody_GetBodyReplaysTheNewBytes(t *testing.T) {
	const original = `{"model":"m","messages":[{"role":"user","content":"SENSITIVE"}]}`
	const rewritten = `{"model":"m","messages":[{"role":"user","content":"{{MASKED_1}}"}]}`

	r, err := http.NewRequest(http.MethodPost, "http://x/v1/chat/completions", strings.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	// Stand in for the group lane: GetBody replays the ORIGINAL buffer.
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(original)), nil }

	setRequestBody(r, []byte(rewritten))

	if r.ContentLength != int64(len(rewritten)) {
		t.Errorf("ContentLength = %d, want %d", r.ContentLength, len(rewritten))
	}
	body, _ := io.ReadAll(r.Body)
	if string(body) != rewritten {
		t.Fatalf("Body = %q, want the rewritten bytes", body)
	}
	if r.GetBody == nil {
		t.Fatal("GetBody is nil; net/http cannot retry this request at all")
	}
	replay, err := r.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(replay)
	if string(got) == original {
		t.Fatal("GetBody still replays the PRE-rewrite bytes — a retry would undo the rewrite " +
			"(for the compliance filter that means sending the unmasked prompt upstream)")
	}
	if string(got) != rewritten {
		t.Fatalf("GetBody replayed %q, want the rewritten bytes", got)
	}
}

// TestSetRequestBody_GetBodyIsRepeatable — net/http may call GetBody more than
// once (redirect, then retry).
func TestSetRequestBody_GetBodyIsRepeatable(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "http://x/", strings.NewReader("old"))
	setRequestBody(r, []byte("new"))
	for i := 0; i < 3; i++ {
		rc, err := r.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		if string(b) != "new" {
			t.Fatalf("call %d replayed %q, want \"new\"", i+1, b)
		}
	}
}
