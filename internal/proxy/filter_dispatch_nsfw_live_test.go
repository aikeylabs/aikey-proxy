package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// TestApplyInboundFilter_LiveDetector_NSFW proves the SERVER-DISTRIBUTED nsfw
// lexicon path end-to-end (regression R5 of bugfix
// 2026-06-08-nsfw-builtin-packs-distribution-and-display):
//
//	mock master /v1/packs/changed (one active nsfw pack)
//	  → real detector puller pulls + merges into the engine
//	  → nsfw prompt through applyInboundFilter
//	  → masked / blocked (the distributed pack actually intercepts)
//
// This is the distributed-pack analog of TestApplyInboundFilter_LiveDetector,
// which only exercises the EMBEDDED baseline. It is the test that answers the
// open question "does a pulled nsfw pack actually intercept, or is it score-only
// / not merged into the engine?". Zero external LLM cost.
//
// Guarded by AIKEY_TEST_DETECTOR_BINARY like the other live tests.
func TestApplyInboundFilter_LiveDetector_NSFW(t *testing.T) {
	bin := os.Getenv("AIKEY_TEST_DETECTOR_BINARY")
	if bin == "" {
		t.Skip("set AIKEY_TEST_DETECTOR_BINARY to the built detector binary to run the live nsfw test")
	}

	// A clearly-political phrase from the nsfw lexicon. category "political" maps
	// to NSFW_POLITICAL via mapCategoryToEntity (top-level category form).
	const word = "一党专政"

	// Mock master: serve exactly one active built-in nsfw pack, mirroring the real
	// /v1/packs/changed wire shape (internal/packs/types.go changedResponse). The
	// phrase carries the word directly (the detector splits a phrase on \n; a
	// single word is the degenerate case).
	resp := `{"packs":[{"pack":{"pack_id":"r5-nsfw","pack_kind":"built-in","tenant_id":"builtin",` +
		`"name":"R5 NSFW","version":1,"status":"active","applicable_roles":[],"action_matrix":[]},` +
		`"rules":[],"phrases":[{"phrase_id":"r5p","pack_id":"r5-nsfw","phrase":"` + word + `",` +
		`"severity":"high","category":"political","confidence":60,"source_role":"compliance"}]}],"max_version":1}`
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(resp))
	}))
	defer master.Close()

	// Point the detector's pack puller at the mock + poll fast so the pull lands
	// shortly after spawn.
	t.Setenv("AIKEY_PACK_MASTER_URL", master.URL)
	t.Setenv("AIKEY_PACK_POLL_INTERVAL", "300ms")

	hook := apphook.NewChildHook(&apphook.ChildHookConfig{
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

	p := &Proxy{filterHook: hook}
	body := `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"请评论` + word + `这个话题"}]}`

	// The pulled pack lands asynchronously after spawn; poll applyInboundFilter
	// until the nsfw word is intercepted, or fail after a generous deadline.
	deadline := time.Now().Add(12 * time.Second)
	var forwarded string
	for time.Now().Before(deadline) {
		r := newReq(body)
		w := httptest.NewRecorder()
		proceed := p.applyInboundFilter(w, r, "claude-3-5-sonnet", "personal", "", "", discardLogger())
		if !proceed {
			// Block is also a valid interception verdict.
			t.Logf("NSFW intercepted via BLOCK (status=%d) — distributed pack effective", w.Code)
			return
		}
		forwarded = readReqBody(t, r)
		if !strings.Contains(forwarded, word) {
			t.Logf("NSFW masked OK — distributed pack effective:\n%s", forwarded)
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("nsfw word %q still present after deadline — the server-distributed pack was "+
		"NOT pulled/merged into the engine, or nsfw is not intercepted (score-only). forwarded:\n%s",
		word, forwarded)
}
