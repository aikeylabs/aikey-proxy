// filter_pool_live_test.go — LIVE acceptance for the filter WORKER POOL.
//
// WHY THIS FILE EXISTS (2026-08-14).
//
// The `filter_hook` health block landed on 2026-08-13 with a full hermetic
// suite (diagnostics_filter_hook_test.go) and ZERO live coverage: the one
// scenario the whole block exists for — "a worker really died, does the
// endpoint say so, and what happens to the requests that were routed to it" —
// had never been executed against real detector processes. The three live
// tests in this package all SKIPped in that round because the detector binary
// was not built.
//
// This harness closes that. It runs the REAL ai-compliance-detector as an M=3
// pool, kills one worker's OS process, and then asserts on BOTH planes at once:
//
//	control plane : GET /v1/diagnostics/pipeline over a real socket
//	                → status=partial, workers_healthy=2/3, workers[1] names why
//	data plane    : N probes through the REAL applyInboundFilter
//	                → how many forwarded RAW PII to the (imaginary) upstream
//
// The data-plane number is the one that matters. Before the B39 fix it was
// N/3 — round-robin kept feeding the dead worker, whose Detect fails open, so
// that share of user content reached the upstream un-inspected. See
// workflow/CI/e2e/cases/2026-08-14-合规检测器池死worker活体验收.md for the
// recorded red baseline and the four-phase diff.
//
// Run:  make -f workflow/CI/Makefile p4-filter-pool-live
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// b39PoolSize is 3, not 2, on purpose. With M=2 a "the dead worker got half the
// traffic" observation is indistinguishable from "every other request failed
// for some unrelated reason". With M=3 and worker index 1 killed, the leak
// pattern must be period-3 phase-1 (requests 1, 4, 7, 10 …) — a fingerprint
// that can only be produced by round-robin over the exact slice
// FilterPool.WorkerStatuses() reports, which is the load-bearing claim the
// health block's `workers[]` ordering makes.
const b39PoolSize = 3

// b39VictimIndex is the dispatch slot whose process gets killed.
const b39VictimIndex = 1

// b39Probes per measurement phase — 4 full round-robin cycles.
const b39Probes = 12

// TestFilterPool_LiveDetector_DeadWorkerMustNotReceiveRequests is the live
// four-phase acceptance for review finding B39.
//
// Phases (每阶段都落盘, 见 forensic dir logged below):
//
//	pre       3/3 healthy  → endpoint `ok`,      probes leak 0
//	action    kill worker 1's process (and remove its binary so lazyRecover
//	          cannot silently undo the fault mid-measurement)
//	post      2/3 healthy  → endpoint `partial`, probes leak ??  ← THE NUMBER
//	assert    restore the binary → the killed worker MUST come back
//	          (self-heal is request-driven; skipping it must not orphan it)
//	          then kill ALL workers → requests must still be served (fail-open)
func TestFilterPool_LiveDetector_DeadWorkerMustNotReceiveRequests(t *testing.T) {
	// The door seals the four $HOME-rooted detector inputs before any worker is
	// spawned. It matters here for a reason the content tests do not have: this
	// harness measures a LEAK COUNT, and a host pack cache or a policy.json ops
	// override changes which probes get masked — i.e. it would move the very
	// number the B39 assertion is about.
	bin, sealed := liveDetectorBinary(t, "the live pool test")
	if runtime.GOOS == "windows" {
		t.Skip("live pool harness kills child processes via pgrep/kill (Unix); the code under test is OS-agnostic")
	}

	forensic := b39ForensicDir(t)
	t.Logf("forensic dir (kept on pass AND fail): %s", forensic)

	// Each worker gets its OWN path to the same binary (a symlink), which is the
	// only handle this harness needs to (a) find exactly one worker's PID and
	// (b) make exactly one worker un-respawnable. Nothing about the pool or the
	// detector is faked.
	paths := make([]string, b39PoolSize)
	workers := make([]*apphook.ChildHook, b39PoolSize)
	for i := range paths {
		paths[i] = filepath.Join(forensic, fmt.Sprintf("detector-w%d", i))
		if err := os.Symlink(bin, paths[i]); err != nil {
			t.Fatalf("symlink worker %d: %v", i, err)
		}
		workers[i] = apphook.NewChildHook(&apphook.ChildHookConfig{
			Name:       "ai-compliance-detector",
			BinaryPath: paths[i],
			// Same budget the other live tests use: real char+token CRF NER needs
			// far more than the 1ms apphook default. Too tight → fail-open, which
			// would make this test count "slow" as "dead".
			Timeout:      500 * time.Millisecond,
			ReadyTimeout: 15 * time.Second,
		})
	}
	pool := apphook.NewFilterPool("ai-compliance-detector", workers)
	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("start pool: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = pool.Shutdown(ctx)
		cancel()
	}()

	p := &Proxy{filterHook: pool}
	// A real socket, so the assertions below travel the same wire an operator's
	// `curl` does (health-signal-surface: the signal must be readable from
	// OUTSIDE the process, not via a Go method call).
	srv := httptest.NewServer(http.HandlerFunc(p.handleDiagnosticsPipeline))
	defer srv.Close()
	endpoint := srv.URL + "/v1/diagnostics/pipeline"
	t.Logf("live diagnostics endpoint: %s", endpoint)

	// Anti-regression: the workers must confirm they resolved the sealed home,
	// BEFORE the pre-phase leak count is taken. Asserted here rather than at the
	// end because the last phase deliberately kills every worker — after that
	// there is nobody left to ask.
	sealed.AssertHeld(t, pool)

	// ── PHASE pre ────────────────────────────────────────────────────────────
	pre := b39Fetch(t, endpoint, forensic, "pre")
	if pre.Status != FilterHookOK || pre.WorkersHealthy != b39PoolSize {
		t.Fatalf("[pre] want status=ok %d/%d, got status=%s %d/%d — the pool did not come up, "+
			"nothing after this measures what it claims to",
			b39PoolSize, b39PoolSize, pre.Status, pre.WorkersHealthy, pre.WorkersTotal)
	}
	preRun := b39Probe(t, p, "pre", b39Probes)
	b39Save(t, forensic, "probes-pre.txt", preRun.table())
	t.Logf("[pre] %s", preRun)
	if preRun.leaked > 0 {
		t.Fatalf("[pre] %d/%d probes forwarded RAW PII with a fully healthy pool — the fixture "+
			"is not being masked at all, so the post-phase count would be meaningless.\n%s",
			preRun.leaked, b39Probes, preRun.table())
	}

	// ── PHASE action ─────────────────────────────────────────────────────────
	// Order is load-bearing: remove the binary BEFORE killing the process.
	// lazyRecover is triggered by traffic and would otherwise respawn the victim
	// mid-measurement, turning a deterministic fault into a race.
	victimPath := paths[b39VictimIndex]
	victimPID := b39PIDOf(t, victimPath)
	if err := os.Remove(victimPath); err != nil {
		t.Fatalf("[action] remove victim binary: %v", err)
	}
	b39Kill(t, victimPID)
	t.Logf("[action] killed worker %d (pid=%d, path=%s) and removed its binary so it stays down",
		b39VictimIndex, victimPID, victimPath)

	// ── PHASE post ───────────────────────────────────────────────────────────
	post := b39Await(t, endpoint, forensic, "post", 20*time.Second, func(h FilterHookHealth) bool {
		return h.WorkersHealthy == b39PoolSize-1
	})
	t.Logf("[post] endpoint: status=%s %d/%d", post.Status, post.WorkersHealthy, post.WorkersTotal)
	for _, w := range post.Workers {
		t.Logf("[post]   worker %d healthy=%v reason=%q restarts=%d",
			w.Index, w.Healthy, w.DegradedReason, w.RestartCount)
	}
	// The one `curl` transcript that goes into the archived case file.
	b39Curl(t, endpoint, forensic, "curl-post.json")

	if post.Status != FilterHookPartial {
		t.Errorf("[post] want status=%q with one worker down, got %q — the health block collapsed "+
			"the partial state that is the whole reason it exists", FilterHookPartial, post.Status)
	}
	if post.WorkersHealthy != b39PoolSize-1 || post.WorkersTotal != b39PoolSize {
		t.Errorf("[post] want workers_healthy=%d/%d, got %d/%d",
			b39PoolSize-1, b39PoolSize, post.WorkersHealthy, post.WorkersTotal)
	}
	victim := post.Workers[b39VictimIndex]
	if victim.Healthy {
		t.Errorf("[post] workers[%d] still reports healthy after its process was killed — either the "+
			"read loop did not notice, or workers[] is NOT in dispatch order and this index is a "+
			"different process than the one we killed", b39VictimIndex)
	}
	// The cause must be the child's own enumerated reason, not a placeholder: a
	// killed process is observed by the read loop as read_failed (`ak doctor`
	// renders it as "crashed", remedy = restart the proxy).
	if !strings.HasPrefix(victim.DegradedReason, "read_failed") {
		t.Errorf("[post] workers[%d].degraded_reason = %q, want a read_failed:* cause for a killed "+
			"child — an unrecognized cause makes `ak doctor` fall back to its generic hint",
			b39VictimIndex, victim.DegradedReason)
	}
	for i, w := range post.Workers {
		if i != b39VictimIndex && !w.Healthy {
			t.Errorf("[post] workers[%d] is also down (reason=%q) — the harness killed exactly one "+
				"process, so the leak arithmetic below no longer holds", i, w.DegradedReason)
		}
	}

	postRun := b39Probe(t, p, "post", b39Probes)
	b39Save(t, forensic, "probes-post.txt", postRun.table())
	t.Logf("[post] %s", postRun)
	t.Logf("[post] probe table (leak = the request whose content reached the upstream un-inspected):\n%s",
		postRun.table())

	// ── PHASE assertion 1: the data plane ────────────────────────────────────
	//
	// 🔴 THE B39 ASSERTION. A worker the health endpoint calls dead must not be
	// handed user content. Before the fix this printed 4/12 with the leaks at
	// requests 1, 4, 7, 10 — period 3, phase 1 — which is simultaneously the
	// proof that WorkerStatuses()[1] IS dispatch slot 1.
	if postRun.leaked > 0 {
		t.Errorf("🔴 B39: %d/%d probes were dispatched to the DEAD worker and forwarded RAW PII "+
			"upstream un-inspected (leak positions %v, period-%d fingerprint of round-robin over a "+
			"pool that includes dead workers).\n%s",
			postRun.leaked, b39Probes, postRun.leakPositions, b39PoolSize, postRun.table())
	}

	// ── PHASE assertion 2: the self-heal must survive being skipped ───────────
	//
	// 🔴 THE PARADOX. lazyRecover is triggered BY REQUESTS. Skipping a degraded
	// worker removes the only thing that used to wake it, so a naive "skip the
	// dead ones" turns a transient degrade into a permanent amputation. The fix
	// keeps traffic as the trigger but decouples it from the payload: pick()
	// nudges the workers it skips. This phase is the proof — the victim gets
	// ZERO requests (assertion 1) and must STILL come back.
	if err := os.Symlink(bin, victimPath); err != nil {
		t.Fatalf("[recover] restore victim binary: %v", err)
	}
	healRun, healed := b39ProbeUntil(t, p, endpoint, forensic, 60*time.Second, func(h FilterHookHealth) bool {
		return h.WorkersHealthy == b39PoolSize
	})
	b39Save(t, forensic, "probes-heal.txt", healRun.table())
	t.Logf("[recover] %s", healRun)
	if !healed {
		t.Fatalf("🔴 SELF-HEAL PARADOX: worker %d never came back after its binary was restored, "+
			"even though %d requests flowed through the pool. Skipping a degraded worker must not "+
			"orphan it — pick() has to nudge the workers it skips.\n%s",
			b39VictimIndex, healRun.total, healRun.table())
	}
	recovered := b39Fetch(t, endpoint, forensic, "healed")
	t.Logf("[recover] endpoint: status=%s %d/%d, worker %d restarts=%d",
		recovered.Status, recovered.WorkersHealthy, recovered.WorkersTotal,
		b39VictimIndex, recovered.Workers[b39VictimIndex].RestartCount)
	if recovered.Status != FilterHookOK {
		t.Errorf("[recover] want status=ok after the worker came back, got %s", recovered.Status)
	}
	if recovered.Workers[b39VictimIndex].RestartCount == 0 {
		t.Errorf("[recover] workers[%d].restart_count is 0 — it reports healthy without ever having "+
			"been respawned, which means the endpoint is describing a different process than the one "+
			"we killed", b39VictimIndex)
	}
	if healRun.leaked > 0 {
		t.Errorf("[recover] %d/%d probes leaked RAW PII while the pool was healing (positions %v) — "+
			"recovery must not be paid for with coverage.\n%s",
			healRun.leaked, healRun.total, healRun.leakPositions, healRun.table())
	}

	// ── PHASE assertion 3: whole-pool loss must not block the user ────────────
	//
	// 不阻塞用户流程 is the project's top principle and it outranks detection.
	// With every worker dead the pool has nobody to route to; the contract is
	// "serve, fail open, and SAY SO", never "refuse".
	for i, path := range paths {
		pid := b39PIDOf(t, path)
		if err := os.Remove(path); err != nil {
			t.Fatalf("[alldead] remove worker %d binary: %v", i, err)
		}
		b39Kill(t, pid)
	}
	dead := b39Await(t, endpoint, forensic, "alldead", 20*time.Second, func(h FilterHookHealth) bool {
		return h.WorkersHealthy == 0
	})
	t.Logf("[alldead] endpoint: status=%s %d/%d reason=%q",
		dead.Status, dead.WorkersHealthy, dead.WorkersTotal, dead.Reason)
	if dead.Status != FilterHookDegraded {
		t.Errorf("[alldead] want status=%q with every worker dead, got %q", FilterHookDegraded, dead.Status)
	}
	deadRun := b39Probe(t, p, "alldead", b39PoolSize)
	b39Save(t, forensic, "probes-alldead.txt", deadRun.table())
	t.Logf("[alldead] %s", deadRun)
	if deadRun.blocked > 0 || deadRun.total != b39PoolSize {
		t.Errorf("🔴 %d/%d requests were BLOCKED with the whole pool dead. A filter that cannot run "+
			"must degrade to pass-through, never fail the user's request (方案 §6 #11).\n%s",
			deadRun.blocked, deadRun.total, deadRun.table())
	}
	if deadRun.leaked != deadRun.total {
		t.Errorf("[alldead] %d/%d probes were masked with NO live worker — impossible; the harness "+
			"is measuring something other than what the detector did", deadRun.total-deadRun.leaked, deadRun.total)
	}
}

// ─── harness ────────────────────────────────────────────────────────────────

// b39Run is one measurement phase's outcome.
type b39Run struct {
	phase         string
	total         int
	leaked        int // forwarded body still contained the raw PII → un-inspected
	blocked       int // applyInboundFilter refused the request (must never happen)
	leakPositions []int
	rows          []string
}

func (r b39Run) String() string {
	return fmt.Sprintf("phase=%s probes=%d leaked(un-inspected)=%d blocked=%d leak_positions=%v",
		r.phase, r.total, r.leaked, r.blocked, r.leakPositions)
}

func (r b39Run) table() string {
	return fmt.Sprintf("%s\n%s\n", r.String(), strings.Join(r.rows, "\n"))
}

// b39Probe sends n single-message requests through the REAL applyInboundFilter
// and counts how many were forwarded with their PII intact.
//
// One user message per request on purpose: applyInboundFilter runs one Detect
// per content piece, so 1 request = 1 pool dispatch and the request index is
// directly comparable to the round-robin cursor.
//
// The e-mail local part varies per probe so no verdict can be reused (the
// per-piece cache is off here anyway, but a fixed payload would leave that
// invariant resting on a default).
func b39Probe(t *testing.T, p *Proxy, phase string, n int) b39Run {
	t.Helper()
	run := b39Run{phase: phase}
	for i := 1; i <= n; i++ {
		// Non-reserved domain on purpose: RFC 2606 addresses (example.com …) are
		// capped at warn by the detector's non_live_value_ceiling stage, so a
		// reserved domain would look exactly like a fail-open.
		email := fmt.Sprintf("john.doe.%s.%d@aikey-fixture.cn", phase, i)
		body := `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":` +
			`"Please verify the contact email ` + email + ` for the account"}]}`
		r := newReq(body)
		w := httptest.NewRecorder()
		proceed := p.applyInboundFilter(w, r, "claude-3-5-sonnet", "personal", "", "", "", "", "", discardLogger())
		run.total++
		verdict := "masked"
		if !proceed {
			run.blocked++
			verdict = "BLOCKED"
			run.rows = append(run.rows, fmt.Sprintf("  #%02d → %s (status=%d)", i, verdict, w.Code))
			continue
		}
		if strings.Contains(readReqBody(t, r), email) {
			run.leaked++
			run.leakPositions = append(run.leakPositions, i)
			verdict = "LEAKED (raw PII forwarded → dispatched to a worker that could not inspect it)"
		}
		run.rows = append(run.rows, fmt.Sprintf("  #%02d → %s", i, verdict))
	}
	return run
}

// b39ProbeUntil keeps probing (which is also what drives the request-triggered
// self-heal) until the endpoint satisfies want, or the budget expires.
func b39ProbeUntil(t *testing.T, p *Proxy, endpoint, forensic string, budget time.Duration,
	want func(FilterHookHealth) bool) (b39Run, bool) {
	t.Helper()
	run := b39Run{phase: "recover"}
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		one := b39Probe(t, p, "recover", 1)
		run.total += one.total
		run.blocked += one.blocked
		if one.leaked > 0 {
			run.leaked += one.leaked
			run.leakPositions = append(run.leakPositions, run.total)
		}
		// Renumber: b39Probe restarts at #01 for each single-shot call, and a table
		// of fifteen "#01" lines is unreadable evidence.
		row := strings.TrimSpace(strings.Join(one.rows, ""))
		run.rows = append(run.rows, fmt.Sprintf("  #%02d%s", run.total, strings.TrimPrefix(row, "#01")))
		if want(b39Fetch(t, endpoint, forensic, "")) {
			return run, true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return run, false
}

// b39Fetch reads the live endpoint over HTTP and decodes the real JSON. snap!=""
// also saves the raw bytes into the forensic dir.
func b39Fetch(t *testing.T, endpoint, forensic, snap string) FilterHookHealth {
	t.Helper()
	resp, err := http.Get(endpoint) //nolint:noctx // loopback test client
	if err != nil {
		t.Fatalf("GET %s: %v", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", endpoint, resp.StatusCode)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode %s: %v", endpoint, err)
	}
	if snap != "" {
		b39Save(t, forensic, "pipeline-"+snap+".json", string(raw))
	}
	var d PipelineDiagnostics
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal PipelineDiagnostics: %v\nraw: %s", err, raw)
	}
	return d.FilterHook
}

// b39Await polls the endpoint until want holds. It exists so the harness never
// asserts on a state the read loop has not observed yet (a killed child is
// noticed asynchronously, on the reader's next failed read).
func b39Await(t *testing.T, endpoint, forensic, snap string, budget time.Duration,
	want func(FilterHookHealth) bool) FilterHookHealth {
	t.Helper()
	deadline := time.Now().Add(budget)
	var last FilterHookHealth
	for time.Now().Before(deadline) {
		last = b39Fetch(t, endpoint, forensic, "")
		if want(last) {
			return b39Fetch(t, endpoint, forensic, snap)
		}
		time.Sleep(100 * time.Millisecond)
	}
	b39Save(t, forensic, "pipeline-"+snap+"-TIMEOUT.json", fmt.Sprintf("%+v", last))
	t.Fatalf("endpoint never reached the awaited state within %s; last: status=%s %d/%d",
		budget, last.Status, last.WorkersHealthy, last.WorkersTotal)
	return last
}

// b39PIDOf finds the single live process started from path. Fails loudly rather
// than returning 0 — a harness that silently kills nothing would report a green
// that means nothing.
func b39PIDOf(t *testing.T, path string) int {
	t.Helper()
	out, err := exec.Command("pgrep", "-f", path).Output()
	if err != nil {
		t.Fatalf("pgrep -f %s: %v (no live worker process for this path?)", path, err)
	}
	fields := strings.Fields(string(out))
	pids := make([]int, 0, len(fields))
	for _, f := range fields {
		pid, convErr := strconv.Atoi(f)
		if convErr != nil || pid == os.Getpid() {
			continue
		}
		pids = append(pids, pid)
	}
	if len(pids) != 1 {
		t.Fatalf("pgrep -f %s matched %d processes (%v); expected exactly the one worker", path, len(pids), pids)
	}
	return pids[0]
}

func b39Kill(t *testing.T, pid int) {
	t.Helper()
	proc, err := os.FindProcess(pid)
	if err != nil {
		t.Fatalf("find process %d: %v", pid, err)
	}
	if err := proc.Kill(); err != nil {
		t.Fatalf("kill %d: %v", pid, err)
	}
}

// b39Curl shells out to the real curl so the archived case file carries a
// transcript an operator can reproduce verbatim.
func b39Curl(t *testing.T, endpoint, forensic, name string) {
	t.Helper()
	out, err := exec.Command("curl", "-sS", endpoint).Output()
	if err != nil {
		t.Logf("curl %s failed (non-fatal, the Go client already asserted): %v", endpoint, err)
		return
	}
	b39Save(t, forensic, name, string(out))
	t.Logf("curl -sS %s →\n%s", endpoint, out)
}

// b39ForensicDir is deliberately NOT t.TempDir(): 本地 E2E 规范 requires the
// evidence to survive the run so a failure can be diagnosed afterwards.
func b39ForensicDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("aikey-b39-live-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("forensic dir: %v", err)
	}
	return dir
}

func b39Save(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Logf("save %s: %v", name, err)
	}
}
