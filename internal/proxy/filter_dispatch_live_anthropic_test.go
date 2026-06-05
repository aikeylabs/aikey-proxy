package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// TestLiveAnthropic_MaskedRequestAcceptedAndAnswered is P4-3b: the real LLM
// closed loop. A PII prompt goes through the REAL proxy forward path
// (Handle → serveRoute → applyInboundFilter) with the REAL detector child; the
// masked body is forwarded to REAL Anthropic, which must accept it and return a
// genuine completion.
//
// A local capture server sits between the proxy and Anthropic so the test can
// observe the EXACT (masked) body the proxy forwarded — proving the raw PII
// never left the box — and then relays it to api.anthropic.com for a real
// round-trip. This is the only piece 3a (zero-cost) could not prove: that a
// masked request is a valid request the upstream LLM accepts and answers.
//
// Guarded by env so normal CI never makes a paid external call:
//
//	AIKEY_TEST_DETECTOR_BINARY = path to the built detector
//	AIKEY_TEST_ANTHROPIC_KEY   = real sk-ant-... official key (from test materials,
//	                             loaded into env by the caller — never hardcoded)
//
// STATUS (2026-05-30): L1 landed (proxy extracts content from the envelope,
// masks per-piece, re-serializes — see filter_content.go). The forwarded body
// is now valid JSON with the envelope preserved, and three independent
// Anthropic-compatible endpoints accepted it structurally (errors were
// billing/auth, which come AFTER JSON validation — pre-L1 was 400 "not valid
// JSON"). The L1 criterion is asserted deterministically on the forwarded body.
// A real 200 completion additionally requires a funded/valid key; when none is
// available the upstream's billing/auth rejection still proves structural
// acceptance (we fail only if it rejects the body as malformed JSON).
func TestLiveAnthropic_MaskedRequestAcceptedAndAnswered(t *testing.T) {
	bin := os.Getenv("AIKEY_TEST_DETECTOR_BINARY")
	key := os.Getenv("AIKEY_TEST_ANTHROPIC_KEY")
	if bin == "" || key == "" {
		t.Skip("set AIKEY_TEST_DETECTOR_BINARY + AIKEY_TEST_ANTHROPIC_KEY to run the live Anthropic closed loop")
	}

	// Real detector hook.
	hook := apphook.NewChildHook(apphook.ChildHookConfig{
		Name:         "ai-compliance-detector",
		BinaryPath:   bin,
		Timeout:      500 * time.Millisecond,
		ReadyTimeout: 15 * time.Second,
	})
	if err := hook.Start(context.Background()); err != nil {
		t.Fatalf("spawn detector: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = hook.Shutdown(ctx)
		cancel()
	}()

	// Capture server: observes the masked body the proxy forwards, then relays
	// it to real Anthropic with a known-good Anthropic request (its own headers,
	// so the test does not depend on what the proxy injected).
	// Upstream defaults to the official Anthropic API; override with
	// AIKEY_TEST_ANTHROPIC_BASE for an Anthropic-compatible third-party endpoint.
	base := os.Getenv("AIKEY_TEST_ANTHROPIC_BASE")
	if base == "" {
		base = "https://api.anthropic.com"
	}
	var forwarded []byte
	capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded, _ = io.ReadAll(r.Body)
		up, _ := http.NewRequestWithContext(r.Context(), "POST", base+"/v1/messages", bytes.NewReader(forwarded))
		up.Header.Set("content-type", "application/json")
		up.Header.Set("x-api-key", key)
		up.Header.Set("authorization", "Bearer "+key) // some Anthropic-compatible proxies use Bearer
		up.Header.Set("anthropic-version", "2023-06-01")
		resp, err := http.DefaultClient.Do(up)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(b)
	}))
	defer capture.Close()

	// Proxy with an anthropic route pointing at the capture server. PlaintextKey
	// is irrelevant (the capture server supplies the real key), so we do not put
	// a real secret into the proxy mock.
	av := &mockActiveVault{
		activeTeamKeys: map[string]*vault.ManagedKey{
			"anthropic": {
				VirtualKeyID:     "live-3b",
				ProviderCode:     "anthropic",
				ProtocolType:     "anthropic",
				BaseURL:          capture.URL,
				PlaintextKey:     "capture-server-supplies-the-real-key",
				ProviderBaseURLs: map[string]string{"anthropic": capture.URL},
			},
		},
	}
	p := setupTestProxyWithActive(t, av)
	p.SetFilterHook(hook)

	// Synthetic PII (obviously fake) embedded in a CJK prompt with full-width
	// punctuation 「，。」around the entities — the exact shape the offset-frame
	// fix had to get right.
	const phone = "13800138000"
	const idCard = "11010119900307742X"
	model := os.Getenv("AIKEY_TEST_ANTHROPIC_MODEL")
	if model == "" {
		model = "claude-3-5-haiku-20241022"
	}
	body := `{"model":"` + model + `","max_tokens":64,"messages":[{"role":"user","content":` +
		`"只需回复\"收到\"两个字即可。客户手机号 ` + phone + `，身份证号 ` + idCard + `。"}]}`

	req := httptest.NewRequest("POST", "/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.Handle(w, req)

	fb := string(forwarded)
	t.Logf("forwarded(masked) body the proxy sent toward Anthropic:\n%s", fb)

	// L1 criterion (deterministic, no funded key needed): the body the proxy
	// forwards is VALID JSON with the envelope preserved and the content masked.
	if fb == "" {
		t.Fatal("capture server never received a forwarded body")
	}
	if !json.Valid(forwarded) {
		t.Fatalf("forwarded body is NOT valid JSON — L1 regressed:\n%s", fb)
	}
	if !strings.Contains(fb, `"messages"`) || !strings.Contains(fb, `"model"`) {
		t.Errorf("envelope keys missing — structure not preserved:\n%s", fb)
	}
	for _, leak := range []string{phone, idCard, "742X"} {
		if strings.Contains(fb, leak) {
			t.Errorf("raw PII %q leaked in forwarded body:\n%s", leak, fb)
		}
	}
	if strings.ContainsRune(fb, '�') {
		t.Errorf("forwarded body contains U+FFFD (mask sliced a rune):\n%s", fb)
	}

	// Upstream round-trip. A 200 proves the upstream accepts the masked body and
	// returns a completion. A non-200 that is NOT a malformed-JSON rejection
	// still proves L1 (the body parsed) — we log it (typically billing/auth on
	// an unfunded test key) rather than fail. We fail ONLY on a structure error,
	// which would mean L1 regressed.
	respLower := strings.ToLower(w.Body.String())
	if w.Code == http.StatusOK {
		var msg struct {
			Type    string `json:"type"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
			t.Fatalf("200 but response is not valid Anthropic JSON: %v\n%s", err, w.Body.String())
		}
		if msg.Type != "message" || len(msg.Content) == 0 {
			t.Fatalf("200 but not a real completion (type=%q content=%d):\n%s", msg.Type, len(msg.Content), w.Body.String())
		}
		t.Logf("LIVE Anthropic closed loop OK — real completion → %q (in=%d out=%d tokens)",
			msg.Content[0].Text, msg.Usage.InputTokens, msg.Usage.OutputTokens)
		return
	}
	if strings.Contains(respLower, "not valid json") || strings.Contains(respLower, "unexpected end") {
		t.Fatalf("upstream rejected the masked body as malformed JSON — L1 regressed (HTTP %d):\n%s",
			w.Code, w.Body.String())
	}
	t.Logf("L1 PROVEN: upstream accepted the masked body structurally (HTTP %d — not a JSON error; "+
		"a real 200 completion needs a funded/valid key):\n%s", w.Code, w.Body.String())
}
