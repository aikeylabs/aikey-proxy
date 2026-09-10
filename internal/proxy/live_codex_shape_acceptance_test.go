package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	_ "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator/pairs/openai_responses"
	"github.com/tidwall/gjson"
)

// live_codex_shape_acceptance_test.go — the ONE verification the dialect bridge
// cannot do for itself.
//
// # What gap this closes
//
// Every other test of the /chat/completions → /responses direction runs against
// a MOCK standing in for chatgpt.com/backend-api/codex. The translation is
// modelled on good evidence — the conversation-audit parser built from live
// codex traffic, the resident mock provider's shapes, the measured rule table
// in codex_shape_normalize.go — but no test has ever put the translated body in
// front of the real backend. Until one does, "the bridge works" means "the
// bridge works against our idea of codex".
//
// This test closes that by dialing the real thing. It cannot run in CI and is
// not meant to: it needs a real ChatGPT OAuth credential, which only the
// operator has.
//
// # How to run it
//
//	AIKEY_LIVE_CODEX_TOKEN='<access token>' \
//	AIKEY_LIVE_CODEX_ACCOUNT_ID='<ChatGPT account uuid>' \
//	AIKEY_LIVE_CODEX_CONFIRM=yes-spend-one-request \
//	go test ./internal/proxy/ -run TestLiveCodexAcceptsTheBridgedShape -count=1 -v
//
// Both the token and the confirmation are required, and the test skips loudly
// without them, so it can never fire by accident from a plain `go test ./...`.
//
// # What it prints, and what it will not print
//
// Shapes only. The request body is echoed with every text value replaced by its
// length, the response is reported as the SEQUENCE of SSE event types plus the
// token counts, and an upstream refusal is echoed because diagnosing one is the
// entire point.
//
// It never prints, logs or writes: the access token, the account id, the prompt,
// or a single byte of the model's answer. There is no file output.
//
// # Cost
//
// ONE request, ~10 output tokens, non-persisted (store:false). It bills the
// operator's subscription; the confirmation variable is there to say so.
func TestLiveCodexAcceptsTheBridgedShape(t *testing.T) {
	token := strings.TrimSpace(os.Getenv("AIKEY_LIVE_CODEX_TOKEN"))
	confirm := strings.TrimSpace(os.Getenv("AIKEY_LIVE_CODEX_CONFIRM"))
	if token == "" || confirm != "yes-spend-one-request" {
		t.Skip("live codex acceptance is OPT-IN: set AIKEY_LIVE_CODEX_TOKEN and " +
			"AIKEY_LIVE_CODEX_CONFIRM=yes-spend-one-request (see this file's header)")
	}
	accountID := strings.TrimSpace(os.Getenv("AIKEY_LIVE_CODEX_ACCOUNT_ID"))

	// ── 1. A plain Chat Completions request, of the shape the bridge exists to
	// serve. max_tokens / temperature are included ON PURPOSE: the measured rule
	// table says the backend rejects both, so this also verifies that the strip
	// in normalizeCodexRequest is what keeps such a request servable.
	inbound := []byte(`{
		"model": "gpt-5-codex",
		"stream": true,
		"max_tokens": 16,
		"temperature": 0.2,
		"messages": [
			{"role": "system", "content": "Reply with the single word: ok"},
			{"role": "user", "content": "ping"}
		]
	}`)

	// ── 2. The REAL translator. Not a re-implementation: importing the pair is
	// what makes a green result mean something about shipped code.
	translated, tErr := translator.DefaultRegistry().TranslateRequest(
		context.Background(), translator.FormatOpenAI, translator.FormatOpenAIResponses,
		gjson.GetBytes(inbound, "model").String(), inbound, true)
	if tErr != nil {
		t.Fatalf("translation refused before any request was made: %s (param=%s) %s",
			tErr.Code, tErr.Param, tErr.Message)
	}

	// ── 3. The REAL pre-dial pipeline: shape normalization, then the codex
	// persona headers, exactly as resolveOAuthUpstream + injectCodexOAuth do.
	// codexUpstreamBaseURL carries a loopback-only test hook, which is what lets
	// this script itself be rehearsed against a rule-enforcing fake before an
	// operator spends a real request on it. The host is echoed and every verdict
	// below names it, so a rehearsal can never read as a live result.
	upstream := codexUpstreamBaseURL()
	req, err := http.NewRequest(http.MethodPost, upstream+"/responses", bytes.NewReader(translated))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", "application/json")
	req = normalizeCodexRequest(req)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("originator", "codex_cli_rs")
	if accountID != "" {
		req.Header.Set("ChatGPT-Account-Id", accountID)
	}

	wire, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	req.Body = io.NopCloser(bytes.NewReader(wire))
	req.ContentLength = int64(len(wire))
	t.Logf("① what actually goes on the wire (text redacted to lengths):\n%s", redactText(wire))

	// ── 4. Dial the real backend. One request, short deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := (&http.Client{}).Do(req.WithContext(ctx))
	if err != nil {
		t.Fatalf("could not reach the codex backend: %v", err)
	}
	defer resp.Body.Close()

	live := strings.Contains(upstream, "chatgpt.com")
	who := "REHEARSAL upstream " + upstream + " (NOT the real backend)"
	if live {
		who = "the real ChatGPT Codex backend"
	}
	t.Logf("② %s answered HTTP %d, content-type %q", who, resp.StatusCode, resp.Header.Get("Content-Type"))
	if h := resp.Header.Get("X-Aikey-Normalized"); h != "" {
		t.Logf("   fields the normalizer removed before dialing: %s", h)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		t.Fatalf("%s REFUSED the bridged shape.\n"+
			"status=%d\nbody=%s\n\n"+
			"This is the answer the mocks could not give. The body above names the field "+
			"it rejected; add it to the strip list in codex_shape_normalize.go or to the "+
			"refusal list in the openai_responses pair, depending on whether the caller "+
			"can be served without it.", who, resp.StatusCode, body)
	}

	// ── 5. Report the SSE lifecycle as a sequence of event types. No content.
	var (
		seq       []string
		sawText   bool
		inTok     int64
		outTok    int64
		completed bool
	)
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		typ := gjson.Get(payload, "type").String()
		if n := len(seq); n == 0 || seq[n-1] != typ {
			seq = append(seq, typ)
		}
		switch typ {
		case "response.output_text.delta":
			sawText = true
		case "response.completed":
			completed = true
			inTok = gjson.Get(payload, "response.usage.input_tokens").Int()
			outTok = gjson.Get(payload, "response.usage.output_tokens").Int()
		}
	}
	t.Logf("③ SSE event types, in order: %s", strings.Join(seq, " → "))
	t.Logf("④ usage: input=%d output=%d tokens", inTok, outTok)

	if !sawText {
		t.Error("no response.output_text.delta arrived — the backend accepted the request " +
			"but produced no text; check the event sequence above")
	}
	if !completed {
		t.Error("no response.completed arrived — the stream did not terminate the way the " +
			"bridge's translator expects, which is what tells a Chat Completions client the turn is over")
	}
	if inTok == 0 && outTok == 0 {
		t.Error("response.completed carried no usage — usage extraction (and therefore billing) " +
			"reads exactly this field")
	}
	if !t.Failed() {
		if live {
			t.Log("✅ the real ChatGPT Codex backend ACCEPTED the bridged shape and streamed a " +
				"complete, billable turn — this is the gap the mocks could not close")
		} else {
			t.Logf("✅ REHEARSAL PASSED against %s. This proves the SCRIPT works; it proves "+
				"NOTHING about the real backend. Re-run without AIKEY_PROXY_TEST_CODEX_BASE_URL "+
				"and with a real credential to close that gap.", upstream)
		}
	}
}

// redactText replaces every string value in a JSON body with a length marker,
// so the shape can be shown without showing the prompt.
func redactText(body []byte) string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return "<unparseable>"
	}
	out, _ := json.MarshalIndent(redactValue(v), "", "  ")
	return string(out)
}

func redactValue(v any) any {
	switch x := v.(type) {
	case string:
		return "<" + itoaInt64(int64(len(x))) + " chars>"
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, vv := range x {
			// Keys that carry shape rather than content stay readable.
			switch k {
			case "type", "role", "model", "object", "status":
				m[k] = vv
			default:
				m[k] = redactValue(vv)
			}
		}
		return m
	case []any:
		a := make([]any, len(x))
		for i, vv := range x {
			a[i] = redactValue(vv)
		}
		return a
	default:
		return v
	}
}
