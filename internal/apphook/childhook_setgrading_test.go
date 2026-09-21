package apphook

// === Fences for TODO-188 方案 C — hot-swapping the org grading document into a
// RUNNING child (pipewire.OpSetGrading) instead of re-spawning the pool ===
//
// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// task-execution/runs/todo-188-design.md (§C.3 + §五 拍板记录).
//
// What the parent must get right, and what these pin:
//
//  1. It moves NOTHING until the child confirms (parse_ok=true AND the token is
//     the digest of the bytes it sent). The verdict-cache epoch moving early
//     would let a verdict minted under the OLD ladder be keyed as NEW; the
//     respawn env moving on a refusal would make the next crash-restart cold-
//     parse the refused document — which disables grading (用户拍板 C.7-3: keep
//     the previous document).
//  2. After a confirmed swap the worker's SELF-HEAL respawn uses the new
//     document. Otherwise a crash quietly rolls a worker back to the old ladder
//     while its cache epoch still says new (todo-188-design.md §C.1 暗坑).
//  3. An old child (no OpSetGrading) is recognizable, so the supervisor can fall
//     back to the pre-C full reload.
//
// Real ChildHook, real OS pipe; the child is this test binary re-executed
// (the TestHelperK1Child pattern).

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/pipewire"
)

const (
	gradingChildEnv = "AIKEY_APPHOOK_GRADING_CHILD" // mode: ok | slow-ok | refuse | old
	// gradingTestDocKey stands in for the supervisor's AIKEY_COMPLIANCE_GRADING:
	// this package is business-blind (不变量 #16) and takes the key from its caller.
	gradingTestDocKey = "AIKEY_APPHOOK_TEST_GRADING_DOC"
	gradingSlowAck    = 400 * time.Millisecond
)

// TestHelperGradingChild is not a test: it is the child process for the fences
// below. It enforces "the document in its env" until told otherwise, and reports
// that document in its ListPacks report so a test can see what a RESPAWNED child
// was born with.
func TestHelperGradingChild(t *testing.T) {
	mode := os.Getenv(gradingChildEnv)
	if mode == "" {
		t.Skip("helper process; not a test")
	}
	current := os.Getenv(gradingTestDocKey)
	_, _ = os.Stderr.WriteString("grading-fixture ready\n")
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	for {
		version, payload, err := pipewire.ReadFrame(in)
		if err != nil {
			os.Exit(0)
		}
		if version != pipewire.ProtocolVersion {
			os.Exit(1)
		}
		req, err := pipewire.DecodeRequest(payload)
		if err != nil {
			os.Exit(1)
		}
		res := &pipewire.Response{ReqID: req.ReqID, Action: pipewire.ActionAllow}
		switch req.Op {
		case pipewire.OpListPacks:
			res.Findings, _ = json.Marshal(map[string]string{"born_with": os.Getenv(gradingTestDocKey)})
		case pipewire.OpSetGrading:
			switch mode {
			case "old":
				// An old child's `default:` arm: Allow, empty findings.
			case "refuse":
				res.Findings, _ = json.Marshal(pipewire.GradingApplied{GradingToken: pipewire.GradingToken([]byte(current))})
			default: // ok, slow-ok
				if mode == "slow-ok" {
					time.Sleep(gradingSlowAck)
				}
				current = req.Prompt
				res.Findings, _ = json.Marshal(pipewire.GradingApplied{GradingToken: pipewire.GradingToken([]byte(current)), ParseOK: true})
			}
		}
		if err := pipewire.WriteFrame(out, pipewire.EncodeResponse(res)); err != nil {
			os.Exit(1)
		}
	}
}

// gradingBornDoc is the document every fixture child is spawned with.
const gradingBornDoc = "doc-old"

func gradingChildConfig(mode string) *ChildHookConfig {
	bornWith := gradingBornDoc
	return &ChildHookConfig{
		Name:               "grading-child",
		BinaryPath:         os.Args[0],
		BinaryArgs:         []string{"-test.run", "^TestHelperGradingChild$"},
		ExtraEnv:           []string{gradingChildEnv + "=" + mode, gradingTestDocKey + "=" + bornWith},
		ContentPolicyToken: pipewire.GradingToken([]byte(bornWith)),
		Timeout:            2 * time.Second,
		ReadyTimeout:       15 * time.Second,
	}
}

func startGradingChild(t *testing.T, cfg *ChildHookConfig) *ChildHook {
	t.Helper()
	h := NewChildHook(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("start grading child: %v", err)
	}
	t.Cleanup(func() { _ = h.Shutdown(context.Background()) })
	if !waitFor(5*time.Second, func() bool { _, ok := h.ContentVersion(); return ok }) {
		t.Fatal("the first content-version poll never landed")
	}
	return h
}

// bornWith restarts the child (the self-heal path, restart()) and asks the NEW
// process which document its environment carried.
func bornWith(t *testing.T, h *ChildHook) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := h.restart(ctx); err != nil {
		t.Fatalf("restart: %v", err)
	}
	report, err := h.ListPacks(ctx)
	if err != nil {
		t.Fatalf("ListPacks after restart: %v", err)
	}
	var rep struct {
		BornWith string `json:"born_with"`
	}
	if err := json.Unmarshal(report, &rep); err != nil {
		t.Fatalf("report: %v (%s)", err, report)
	}
	return rep.BornWith
}

func policySuffix(h *ChildHook) string {
	cv, _ := h.ContentVersion()
	if i := strings.LastIndex(cv, "|"); i >= 0 {
		return cv[i+1:]
	}
	return ""
}

// TestChildHook_SetGradingUpdatesRespawnEnv — a confirmed swap rewrites THIS
// worker's respawn env (so a crash-restart is born with the new document), a
// refused one leaves it alone, and a sibling built from the same config is never
// touched (the ExtraEnv slice is shared by every worker NewChildHook built from
// one config — an in-place write would silently rewrite all of them).
//
// 能红: skip the env update on Applied → the first row respawns with "doc-old".
func TestChildHook_SetGradingUpdatesRespawnEnv(t *testing.T) {
	t.Run("applied: respawn is born with the new document", func(t *testing.T) {
		cfg := gradingChildConfig("ok")
		h := startGradingChild(t, cfg)
		sibling := NewChildHook(cfg) // same config, never started
		res := h.SetGrading(context.Background(), gradingTestDocKey, []byte("doc-new"))
		if res.Outcome != GradingPushApplied {
			t.Fatalf("outcome = %v (%v), want applied", res.Outcome, res.Err)
		}
		if got := bornWith(t, h); got != "doc-new" {
			t.Fatalf("the respawned worker was born with %q, want doc-new — a crash would roll it back "+
				"to the old ladder while its cache epoch says new", got)
		}
		for _, kv := range sibling.cfg.ExtraEnv {
			if kv == gradingTestDocKey+"=doc-new" {
				t.Fatal("a sibling worker's env was rewritten through the shared ExtraEnv slice")
			}
		}
	})
	t.Run("refused: respawn keeps the previous document", func(t *testing.T) {
		h := startGradingChild(t, gradingChildConfig("refuse"))
		res := h.SetGrading(context.Background(), gradingTestDocKey, []byte("doc-unreadable"))
		if res.Outcome != GradingPushRefused {
			t.Fatalf("outcome = %v (%v), want refused", res.Outcome, res.Err)
		}
		if got := bornWith(t, h); got != "doc-old" {
			t.Fatalf("after a REFUSED swap the respawn was born with %q — it would cold-parse the "+
				"refused document and run with grading off (用户拍板 C.7-3)", got)
		}
	})
}

// TestChildHook_PolicyTokenMovesOnlyAfterAck — the verdict-cache epoch
// (ContentVersion's policy half) moves at the confirmation, never before it and
// never on a refusal. While the child is still working on the swap, the epoch
// must still name the OLD document: a Detect answered in that window was decided
// under the old ladder, and keying it as new would make it replayable after the
// swap (R-compliance-grading-5.S1 through a new door).
//
// 能红: store the new token before the roundtrip → the in-flight row fails.
func TestChildHook_PolicyTokenMovesOnlyAfterAck(t *testing.T) {
	oldToken := pipewire.GradingToken([]byte("doc-old"))
	newToken := pipewire.GradingToken([]byte("doc-new"))

	t.Run("in flight and after confirmation", func(t *testing.T) {
		h := startGradingChild(t, gradingChildConfig("slow-ok"))
		if got := policySuffix(h); got != oldToken {
			t.Fatalf("spawn-time epoch policy half = %q, want %q", got, oldToken)
		}
		var sawEarly atomic.Bool
		done := make(chan GradingPushResult, 1)
		go func() { done <- h.SetGrading(context.Background(), gradingTestDocKey, []byte("doc-new")) }()
		deadline := time.Now().Add(gradingSlowAck / 2)
		for time.Now().Before(deadline) {
			if policySuffix(h) == newToken {
				sawEarly.Store(true)
			}
			time.Sleep(5 * time.Millisecond)
		}
		res := <-done
		if sawEarly.Load() {
			t.Fatal("the cache epoch named the NEW document before the child confirmed it")
		}
		if res.Outcome != GradingPushApplied || res.Token != newToken {
			t.Fatalf("result = %+v, want applied with %q", res, newToken)
		}
		if got := policySuffix(h); got != newToken {
			t.Fatalf("after confirmation the epoch policy half = %q, want %q", got, newToken)
		}
	})
	t.Run("refused", func(t *testing.T) {
		h := startGradingChild(t, gradingChildConfig("refuse"))
		h.SetGrading(context.Background(), gradingTestDocKey, []byte("doc-new"))
		if got := policySuffix(h); got != oldToken {
			t.Fatalf("a refused swap moved the epoch to %q, want it still at %q", got, oldToken)
		}
	})
}

// TestChildHook_UnknownOpAckIsUnsupported — a child that predates OpSetGrading
// answers through its default arm (Allow, empty findings). That must read as
// "unsupported" — the supervisor's cue to fall back to a full reload — and move
// nothing. Reading it as "refused" would leave the fleet on the old ladder with
// no reload; reading it as "applied" would move the epoch for a document the
// child never saw.
func TestChildHook_UnknownOpAckIsUnsupported(t *testing.T) {
	h := startGradingChild(t, gradingChildConfig("old"))
	res := h.SetGrading(context.Background(), gradingTestDocKey, []byte("doc-new"))
	if res.Outcome != GradingPushUnsupported {
		t.Fatalf("outcome = %v (%v), want unsupported", res.Outcome, res.Err)
	}
	if got := policySuffix(h); got != pipewire.GradingToken([]byte("doc-old")) {
		t.Fatalf("an unsupported push moved the epoch to %q", got)
	}
	if got := bornWith(t, h); got != "doc-old" {
		t.Fatalf("an unsupported push rewrote the respawn env to %q", got)
	}
}

// TestFilterPool_SetGradingReportsEveryWorker — the pool pushes to every worker
// and reports each outcome in dispatch order, so the supervisor can tell "all
// applied" from "some refused" and roll back exactly the ones that applied.
func TestFilterPool_SetGradingReportsEveryWorker(t *testing.T) {
	ok := startGradingChild(t, gradingChildConfig("ok"))
	refuse := startGradingChild(t, gradingChildConfig("refuse"))
	pool := NewFilterPool("grading-pool", []*ChildHook{ok, refuse})
	results := pool.SetGrading(context.Background(), gradingTestDocKey, []byte("doc-new"))
	if len(results) != 2 || results[0].Outcome != GradingPushApplied || results[1].Outcome != GradingPushRefused {
		t.Fatalf("results = %+v, want [applied refused]", results)
	}
}
