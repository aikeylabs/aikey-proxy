package supervisor

// grading_hot_swap_test.go — TODO-188 方案 C, the supervisor's decision table
// (grading_hot_swap.go). Real supervisor state, real FilterPool, real ChildHooks
// over real OS pipes; the detector is this test binary re-executed
// (TestHelperSupervisorGradingChild), so each arm controls exactly one thing:
// what the detector answers to pipewire.OpSetGrading.
//
// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// task-execution/runs/todo-188-design.md (§C.3, §五 拍板记录).
//
// spec: R-compliance-grading-5.1

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/pkg/pipewire"
)

const (
	supGradingChildEnv = "AIKEY_SUPERVISOR_GRADING_CHILD" // ok | refuse | old
	// Two ladders that differ in the ONE member the proxy reads, so "the proxy
	// moved" is observable through ComplianceEscalationRules.
	hotDocA = `{"labels":{"4":"商密"},"ladder":{"4":{"action":"mask"}},"escalation":[{"min_level":4,"min_count":3,"action":"block"}]}`
	hotDocB = `{"labels":{"4":"商密"},"ladder":{"4":{"action":"warn"}},"escalation":[{"min_level":5,"min_count":1,"action":"block"}]}`
)

// TestHelperSupervisorGradingChild is not a test: it is the detector stand-in.
func TestHelperSupervisorGradingChild(t *testing.T) {
	mode := os.Getenv(supGradingChildEnv)
	if mode == "" {
		t.Skip("helper process; not a test")
	}
	current := os.Getenv(gradingEnvKey)
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
			res.Findings = []byte(`{"built_in":[],"pulled":[]}`)
		case pipewire.OpSetGrading:
			switch {
			case mode == "old":
			case mode == "refuse" && req.Prompt != current:
				// Refuses anything new, accepts a push of what it already has
				// (the rollback of a sibling worker pushes the previous document).
				res.Findings, _ = json.Marshal(pipewire.GradingApplied{GradingToken: pipewire.GradingToken([]byte(current))})
			default:
				current = req.Prompt
				res.Findings, _ = json.Marshal(pipewire.GradingApplied{GradingToken: pipewire.GradingToken([]byte(current)), ParseOK: true})
			}
		}
		if err := pipewire.WriteFrame(out, pipewire.EncodeResponse(res)); err != nil {
			os.Exit(1)
		}
	}
}

// hotSwapRig is a supervisor whose active generation runs a FilterPool of
// helper detectors and a proxy, all holding hotDocA — the state the poller
// finds when an administrator then edits the ladder.
type hotSwapRig struct {
	s       *Supervisor
	gen     *generation
	pool    *apphook.FilterPool
	reloads int
}

func newHotSwapRig(t *testing.T, modes ...string) *hotSwapRig {
	t.Helper()
	s := &Supervisor{}
	s.applyComplianceMasterPolicy(true, privacyTierMetadataOnly, false, []byte(hotDocA), true)

	workers := make([]*apphook.ChildHook, len(modes))
	for i, mode := range modes {
		workers[i] = apphook.NewChildHook(&apphook.ChildHookConfig{
			Name:               "grading-sup-child",
			BinaryPath:         os.Args[0],
			BinaryArgs:         []string{"-test.run", "^TestHelperSupervisorGradingChild$"},
			ExtraEnv:           []string{supGradingChildEnv + "=" + mode, gradingEnvKey + "=" + s.gradingEnvValue()},
			ContentPolicyToken: s.gradingContentPolicyToken(),
			Timeout:            2 * time.Second,
			ReadyTimeout:       15 * time.Second,
		})
	}
	pool := apphook.NewFilterPool("ai-compliance-detector", workers)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := pool.Start(ctx); err != nil {
		t.Fatalf("start pool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Shutdown(context.Background()) })
	for _, w := range workers {
		w := w
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, ok := w.ContentVersion(); ok {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("first content-version poll never landed")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	p := &proxy.Proxy{}
	logProxyGradingInstall(p.SetComplianceGrading(s.gradingPolicyJSON()))

	// A real vault with one filter app, so the recorded filter signature can be
	// compared with what syncManagedKeys would compute.
	dbPath, reader := newOpenableVault(t, nil)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE app_records (slug TEXT, filter_stages TEXT, filter_record_allow INTEGER, filter_max_action TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO app_records VALUES ('ai-compliance-detector','["pre_forward"]',0,'full')`); err != nil {
		t.Fatal(err)
	}

	gen := &generation{proxy: p, filterHook: pool, vault: reader}
	s.active.Store(gen)
	if base, ok := computeFilterSig(reader); ok {
		sig := s.filterSigFrom(base)
		s.lastFilterSig.Store(&sig)
	} else {
		t.Fatal("fixture vault: computeFilterSig failed")
	}
	return &hotSwapRig{s: s, gen: gen, pool: pool}
}

// edit is one poll that changes ONLY the grading document, acted on exactly as
// syncComplianceMasterPolicy does — with a reload spy instead of s.Reload.
func (r *hotSwapRig) edit(t *testing.T, doc string) compliancePolicyChange {
	t.Helper()
	change := r.s.applyComplianceMasterPolicy(true, privacyTierMetadataOnly, false, []byte(doc), true)
	r.s.actOnCompliancePolicyChange(context.Background(), change, func(context.Context) error {
		r.reloads++
		return nil
	})
	return change
}

func workerPolicyTokens(pool *apphook.FilterPool) []string {
	statuses := pool.WorkerStatuses()
	out := make([]string, 0, len(statuses))
	for _, st := range statuses {
		cv := st.ContentVersion
		out = append(out, cv[strings.LastIndex(cv, "|")+1:])
	}
	return out
}

func minLevels(p *proxy.Proxy) []int {
	rules := p.ComplianceEscalationRules()
	out := make([]int, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.MinLevel)
	}
	return out
}

// TestGradingChange_HotPushesWithoutNewGeneration — the whole point of C: a
// grading-only change reaches the running detectors and this proxy with NO
// reload and NO new generation, every worker's cache epoch names the new
// document, the proxy's cumulative rule follows, and the recorded filter
// signature already includes the new document (otherwise the next vault tick
// computes a "changed" signature and reloads anyway — one detector generation
// doubling, just 5 s later).
//
// 能红: skip the lastFilterSig rewrite → the signature row fails; route the
// grading-only change to reload → the reload counter fails.
func TestGradingChange_HotPushesWithoutNewGeneration(t *testing.T) {
	r := newHotSwapRig(t, "ok", "ok")
	restartsBefore := []uint64{}
	for _, st := range r.pool.WorkerStatuses() {
		restartsBefore = append(restartsBefore, st.RestartCount)
	}

	change := r.edit(t, hotDocB)
	if !change.grading || change.respawn {
		t.Fatalf("a grading-only edit must be classified grading (not respawn): %+v", change)
	}
	if r.reloads != 0 {
		t.Fatalf("a grading-only change ran %d reload(s) — that is the 2×M-detector window C removes", r.reloads)
	}
	if r.s.active.Load() != r.gen {
		t.Fatal("the active generation was replaced")
	}
	want := pipewire.GradingToken([]byte(hotDocB))
	for i, tok := range workerPolicyTokens(r.pool) {
		if tok != want {
			t.Errorf("worker %d cache epoch names %q, want the new document %q", i, tok, want)
		}
	}
	for i, st := range r.pool.WorkerStatuses() {
		if st.RestartCount != restartsBefore[i] {
			t.Errorf("worker %d was restarted (%d → %d)", i, restartsBefore[i], st.RestartCount)
		}
	}
	if got := minLevels(r.gen.proxy); len(got) != 1 || got[0] != 5 {
		t.Fatalf("the proxy's escalation rules = %v, want the new document's [5] (R-compliance-grading-15: same bytes)", got)
	}
	base, _ := computeFilterSig(r.gen.vault)
	if got, want := *r.s.lastFilterSig.Load(), r.s.filterSigFrom(base); got != want {
		t.Fatalf("recorded filter signature %q != current %q — the next vault tick would reload", got, want)
	}
	if n := r.s.GradingHotSwapRefusals(); n != 0 {
		t.Fatalf("refusal streak = %d after a clean swap", n)
	}
}

// TestGradingChange_OldDetectorFallsBackToReload — a detector that predates
// OpSetGrading answers with an empty findings slot; the supervisor must fall
// back to exactly the pre-C behavior: one full reload, with masterGrading
// holding the new document so the reload spawns with it. Nothing else moved.
//
// 能红: treat "unsupported" as "applied" → no reload, and the old detectors keep
// the old ladder forever while the proxy believes the new one.
func TestGradingChange_OldDetectorFallsBackToReload(t *testing.T) {
	r := newHotSwapRig(t, "old", "old")
	r.edit(t, hotDocB)
	if r.reloads != 1 {
		t.Fatalf("reloads = %d, want exactly 1 (the pre-C path)", r.reloads)
	}
	if got := r.s.gradingEnvValue(); got != hotDocB {
		t.Fatalf("the fallback reload would spawn with %q, want the new document", got)
	}
	if got := minLevels(r.gen.proxy); len(got) != 1 || got[0] != 4 {
		t.Fatalf("the OLD generation's proxy moved to %v before its detectors did", got)
	}
	for i, tok := range workerPolicyTokens(r.pool) {
		if tok != pipewire.GradingToken([]byte(hotDocA)) {
			t.Errorf("worker %d epoch moved to %q without the child confirming", i, tok)
		}
	}
}

// TestGradingChange_RefusedKeepsPreviousEverywhere — 用户拍板 2026-09-21 C.7-3.
// One worker refuses the new document (the other applies it). The whole node
// must end up on the PREVIOUS document: the applying worker rolled back,
// masterGrading restored (so a later reload or crash-restart cannot pick the
// refused document up and cold-parse it into "grading off"), the proxy's rules
// untouched, NO reload, an ERROR, and a refusal streak /health turns into
// degraded. When the master goes back to the document in force, the streak
// clears.
//
// 能红: fall back to reload on refusal → reloads=1 and the env holds the refused
// document; skip the masterGrading restore → the env row fails.
func TestGradingChange_RefusedKeepsPreviousEverywhere(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	r := newHotSwapRig(t, "ok", "refuse")
	r.edit(t, hotDocB)

	if r.reloads != 0 {
		t.Fatalf("a refused document triggered %d reload(s) — the reload would cold-parse it and switch grading OFF", r.reloads)
	}
	if got := r.s.gradingEnvValue(); got != hotDocA {
		t.Fatalf("masterGrading = %q after a refusal, want the previous document restored", got)
	}
	wantA := pipewire.GradingToken([]byte(hotDocA))
	for i, tok := range workerPolicyTokens(r.pool) {
		if tok != wantA {
			t.Errorf("worker %d epoch = %q, want the previous document (the applying worker must be rolled back)", i, tok)
		}
	}
	if got := minLevels(r.gen.proxy); len(got) != 1 || got[0] != 4 {
		t.Fatalf("the proxy moved to %v although its detectors did not (R-compliance-grading-15)", got)
	}
	if n := r.s.GradingHotSwapRefusals(); n != 1 {
		t.Fatalf("refusal streak = %d, want 1", n)
	}
	if !strings.Contains(logs.String(), "level=ERROR") ||
		!strings.Contains(logs.String(), observability.EventComplianceGradingHotSwapRefused) {
		t.Fatalf("a refusal must be an ERROR with its event name; logs:\n%s", logs.String())
	}

	// The next poll carries the same document: retried, refused again, streak grows.
	r.edit(t, hotDocB)
	if n := r.s.GradingHotSwapRefusals(); n != 2 || r.reloads != 0 {
		t.Fatalf("second poll: streak=%d reloads=%d, want 2 / 0", n, r.reloads)
	}
	// The master reverts to the document in force: console and node agree again.
	r.edit(t, hotDocA)
	if n := r.s.GradingHotSwapRefusals(); n != 0 {
		t.Fatalf("streak = %d after the master reverted to the document in force, want 0", n)
	}
}

// TestGradingChange_RespawnValuesStillReload — the split is exact: a change of
// a value that can only reach the detector through its env (here the privacy
// tier) still reloads, even when the grading document changed in the same poll.
func TestGradingChange_RespawnValuesStillReload(t *testing.T) {
	r := newHotSwapRig(t, "ok")
	change := r.s.applyComplianceMasterPolicy(true, 3, false, []byte(hotDocB), true)
	if !change.respawn || change.grading {
		t.Fatalf("tier + grading change must be respawn-only: %+v", change)
	}
	r.s.actOnCompliancePolicyChange(context.Background(), change, func(context.Context) error {
		r.reloads++
		return nil
	})
	if r.reloads != 1 {
		t.Fatalf("reloads = %d, want 1", r.reloads)
	}
}
