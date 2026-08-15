package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/detectortest"
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
//
// HERMETIC BY CONSTRUCTION (sealing correction 2026-08-14) — the binary comes
// from liveDetectorBinary, which seals every $HOME-rooted detector input before
// anything is spawned (see internal/detectortest), and nsfwMockPhraseConfidence
// below makes the served pack self-sufficient. Before that date this test passed
// ONLY on a workstation that already had aikey installed; on a clean machine it
// was red. Do not "simplify" either of those two things away.
func TestApplyInboundFilter_LiveDetector_NSFW(t *testing.T) {
	// The door seals every $HOME-rooted input the detector reads BEFORE it is
	// spawned, so the verdict below is produced by this test's own mock pack and
	// nothing else.
	bin, sealed := liveDetectorBinary(t, "the live nsfw test")

	// A clearly-political phrase from the nsfw lexicon. category "political" maps
	// to NSFW_POLITICAL via mapCategoryToEntity (top-level category form).
	const word = "一党专政"

	// Mock master: serve exactly one active built-in nsfw pack, mirroring the real
	// /v1/packs/changed wire shape (internal/packs/types.go changedResponse). The
	// phrase carries the word directly (the detector splits a phrase on \n; a
	// single word is the degenerate case).
	resp := `{"packs":[{"pack":{"pack_id":"` + nsfwMockPackID + `","pack_kind":"built-in","tenant_id":"builtin",` +
		`"name":"R5 NSFW","version":1,"status":"active","applicable_roles":[],"action_matrix":[]},` +
		`"rules":[],"phrases":[{"phrase_id":"r5p","pack_id":"` + nsfwMockPackID + `","phrase":"` + word + `",` +
		`"severity":"high","category":"political","confidence":` + strconv.Itoa(nsfwMockPhraseConfidence) +
		`,"source_role":"compliance"}]}],"max_version":1}`
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
	// Generic half of the anti-regression pair: the child must confirm it
	// resolved the sealed home. The nsfw-specific half (assertPackIsolationHeld)
	// runs after the verdict, because it also proves the PULL happened.
	sealed.AssertHeld(t, hook)

	p := &Proxy{filterHook: hook}
	body := `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"请评论` + word + `这个话题"}]}`

	// The pulled pack lands asynchronously after spawn; poll applyInboundFilter
	// until the nsfw word is intercepted, or fail after a generous deadline.
	deadline := time.Now().Add(12 * time.Second)
	var forwarded string
	for time.Now().Before(deadline) {
		r := newReq(body)
		w := httptest.NewRecorder()
		proceed := p.applyInboundFilter(w, r, "claude-3-5-sonnet", "personal", "", "", "", "", "", discardLogger())
		if !proceed {
			// Block is also a valid interception verdict.
			assertPackIsolationHeld(t, sealed.PackCacheDir)
			t.Logf("NSFW intercepted via BLOCK (status=%d) — distributed pack effective", w.Code)
			return
		}
		forwarded = readReqBody(t, r)
		if !strings.Contains(forwarded, word) {
			assertPackIsolationHeld(t, sealed.PackCacheDir)
			t.Logf("NSFW masked OK — distributed pack effective:\n%s", forwarded)
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("nsfw word %q still present after deadline — the server-distributed pack was "+
		"NOT pulled/merged into the engine, or nsfw is not intercepted (score-only). forwarded:\n%s",
		word, forwarded)
}

// nsfwMockPackID is the pack the mock master serves. It is asserted on by
// assertPackIsolationHeld, so it must stay distinct from any real built-in
// pack id (`builtin-nsfw-*`).
const nsfwMockPackID = "r5-nsfw"

// nsfwMockPhraseConfidence — WHY THIS MUST STAY ≥ 70 (sealing correction 2026-08-14)
//
// The aggregator fuses a finding group as
//
//	raw = hp_score + hr_max + 0.6 × (hr_sum − hr_max)     (aggregator.go)
//
// For ONE phrase from ONE pack there is exactly one term, so the fused score is
// just this confidence. The action ladder's mask threshold is 70, so a phrase
// carrying less than 70 can never reach `mask` on its own — it lands at `warn`
// and the word is forwarded to the LLM verbatim.
//
// This fixture used to carry 60. It nevertheless went green on developer
// workstations because a SECOND, unrelated political pack in the machine's real
// pack cache (`builtin-nsfw-political`, confidence 50) matched the same span and
// pushed the group to 60 + 0.6×50 = 90. The test was therefore asserting on the
// developer's installed lexicon, not on the pack it served: with an empty cache
// it scored 60 and failed. Raising the fixture to a self-sufficient confidence
// is the fix; the 70 threshold itself is PRODUCT configuration and must not be
// touched to make a test pass.
//
// 95 rather than exactly 70: the LF context scorer can subtract from a raw
// confidence before fusion (AdjustedConfidence), so a fixture sitting exactly on
// the boundary would be one calibration change away from silently returning to
// `warn`. 95 is the same "clearly above the mask threshold" anchor used by the
// sealed detector-side fence
// (ai-compliance-detector/cmd/detector/nsfw_family_enforcement_test.go
// nsfwConfidenceAboveMaskThreshold).
const nsfwMockPhraseConfidence = 95

// assertPackIsolationHeld is the nsfw-SPECIFIC half of the anti-regression pair.
// The generic half (the child confirming it resolved the sealed $HOME) is
// detectortest.Sealed.AssertHeld, which every detector-spawning test calls; this
// one adds what only a test serving its own pack master can prove.
//
// It exists because AIKEY_PACK_CACHE_DIR is read straight from the environment
// and can therefore be honored or ignored independently of $HOME: a refactor, a
// renamed variable, or a config precedence change would silently send this test
// back to the developer's real pack cache while the sealed-home check still
// passed, and the test would keep going green for the borrowed reason it went
// green before 2026-08-14. Two facts are checked:
//
//   - the sealed cache dir actually received the pack snapshot ⇒ the override is
//     live, and the pull really happened (a warm-start from elsewhere would
//     leave this directory empty);
//   - the snapshot holds ONLY the mock pack ⇒ no installed lexicon leaked into
//     the engine, so the verdict above is attributable to the served pack alone.
func assertPackIsolationHeld(t *testing.T, cacheDir string) {
	t.Helper()
	snapshot := filepath.Join(cacheDir, "packs.json")
	data, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatalf("pack isolation broken: sealed cache %s holds no packs.json (%v) — the detector "+
			"did not honor %s, so the verdict came from host state this test does not control",
			snapshot, err, detectortest.PackCacheDirEnv)
	}
	if !strings.Contains(string(data), nsfwMockPackID) {
		t.Fatalf("pack isolation broken: sealed cache %s does not contain the mock pack %q — "+
			"the assertion above was not decided by the pack this test served", snapshot, nsfwMockPackID)
	}
	// `builtin-nsfw-` is the id prefix of the real distributed lexicon packs
	// (builtin-nsfw-political / -porn / -violence / -insult / -vice). Any of them
	// appearing here means host state reached the engine.
	if strings.Contains(string(data), "builtin-nsfw-") {
		t.Fatalf("pack isolation broken: sealed cache %s contains an installed builtin-nsfw pack — "+
			"host lexicon leaked into the engine and the interception above may be borrowed:\n%s",
			snapshot, string(data))
	}
}
