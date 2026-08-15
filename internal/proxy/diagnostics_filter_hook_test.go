package proxy

// diagnostics_filter_hook_test.go — GET /v1/diagnostics/pipeline must let an
// EXTERNAL reader answer two questions the proxy previously only whispered into
// its own log file:
//
//	"is the filter child answering, and if not, WHY?"        (review B5 / B36)
//	"is the verdict cache on, and if not, what fixes it?"    (review B6)
//
// WHY THAT MATTERS. Until 2026-08-13 apphook.Status had no json tags and no
// reader: the write-timeout fix introduced `write_timeout` as a degraded cause
// and `ak doctor` could still only see `available:false` on
// /admin/compliance/packs — so "the child wedged mid-write" and "the child was
// never started" were the same observation, with the cause and the remedy lost.
// And the pack-swap fix switched the verdict cache OFF for any detector too old
// to answer op=ListPacks (correct: a detector that cannot state its ruleset must
// not have verdicts replayed) — a 96%→0 hit-rate cliff whose only outward sign
// was "the proxy got slower".
//
// LAYERING. The apphook side (real ChildHook / real FilterPool producing these
// Status values) is pinned in internal/apphook/status_external_readability_test.go.
// This file pins the PROJECTION: statuses → verdict → JSON. The pool double
// below supplies boundary values to that projection; it is not a substitute for
// the real pool, which is exercised there.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// ─────────────────────────────────────────────────────────────────────────────
// doubles
// ─────────────────────────────────────────────────────────────────────────────

// unitHook is one filter unit with a caller-supplied Status. Used for the states
// that cannot be staged on a developer box without a real wedged child.
type unitHook struct{ st apphook.Status }

func (h *unitHook) Name() string { return "ai-compliance-detector" }
func (h *unitHook) Detect(context.Context, *apphook.Request) *apphook.Response {
	return &apphook.Response{Action: apphook.ActionAllow}
}
func (h *unitHook) Status() *apphook.Status { s := h.st; return &s }

// ContentVersion mirrors ChildHook's rule exactly: a token means cacheable, an
// empty one means fail-safe. Re-stating it here (rather than hard-coding a bool)
// keeps the double honest about the one invariant the endpoint reports on.
func (h *unitHook) ContentVersion() (string, bool) {
	return h.st.ContentVersion, h.st.ContentVersion != ""
}

// poolHook is M units behind one Hook, shaped like apphook.FilterPool: the
// aggregate Status stays "keep serving" while ≥1 unit is up, and WorkerStatuses
// exposes what that aggregate hides.
type poolHook struct{ units []*unitHook }

func (p *poolHook) Name() string { return "ai-compliance-detector" }
func (p *poolHook) Detect(context.Context, *apphook.Request) *apphook.Response {
	return &apphook.Response{Action: apphook.ActionAllow}
}

func (p *poolHook) Status() *apphook.Status {
	healthy := 0
	for _, u := range p.units {
		if u.st.Healthy {
			healthy++
		}
	}
	return &apphook.Status{Healthy: healthy > 0}
}

func (p *poolHook) WorkerStatuses() []*apphook.Status {
	out := make([]*apphook.Status, 0, len(p.units))
	for _, u := range p.units {
		out = append(out, u.Status())
	}
	return out
}

// ContentVersion mirrors FilterPool's fail-safe: a HEALTHY unit that cannot
// state its content set makes the whole pool uncacheable.
func (p *poolHook) ContentVersion() (string, bool) {
	tokens := make([]string, 0, len(p.units))
	for _, u := range p.units {
		v, ok := u.ContentVersion()
		if !ok {
			if u.st.Healthy {
				return "", false
			}
			continue
		}
		tokens = append(tokens, v)
	}
	if len(tokens) == 0 {
		return "", false
	}
	return strings.Join(tokens, "|"), true
}

func healthyUnit(token string) *unitHook {
	return &unitHook{st: apphook.Status{Healthy: true, Version: "detector/1.2.0", ContentVersion: token}}
}

// readFilterHookDiagnostics drives the REAL handler and decodes the REAL wire
// bytes. Reading the struct directly would let a missing json tag pass — and a
// missing json tag is exactly the defect this endpoint block was added to fix.
func readFilterHookDiagnostics(t *testing.T, p *Proxy) PipelineDiagnostics {
	t.Helper()
	w := httptest.NewRecorder()
	p.handleDiagnosticsPipeline(w, httptest.NewRequest(http.MethodGet, "/v1/diagnostics/pipeline", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("diagnostics returned %d, body=%s", w.Code, w.Body.String())
	}
	var out PipelineDiagnostics
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("diagnostics body is not decodable JSON: %v\nbody=%s", err, w.Body.String())
	}
	return out
}

// rawFilterHookBlock returns the endpoint's `filter_hook` object as generic JSON,
// so field NAMES are asserted as wire facts rather than through the Go struct's
// tags (which is the layer that was missing).
func rawFilterHookBlock(t *testing.T, p *Proxy) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	p.handleDiagnosticsPipeline(w, httptest.NewRequest(http.MethodGet, "/v1/diagnostics/pipeline", nil))
	var envelope map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	block, ok := envelope["filter_hook"].(map[string]any)
	if !ok {
		t.Fatalf("no `filter_hook` object on the endpoint — the health signal is still unreadable "+
			"from outside the process. body=%s", w.Body.String())
	}
	return block
}

// ─────────────────────────────────────────────────────────────────────────────
// The four states (B5 / B36)
// ─────────────────────────────────────────────────────────────────────────────

func TestDiagnostics_FilterHook_Healthy(t *testing.T) {
	p := &Proxy{filterHook: &unitHook{st: apphook.Status{Healthy: true, Version: "detector/1.2.0", ContentVersion: "abc123"}}}
	p.SetFilterCacheEnabled(true, 5)

	fh := readFilterHookDiagnostics(t, p).FilterHook
	if fh.Status != FilterHookOK {
		t.Errorf("status = %q, want %q (reason=%q)", fh.Status, FilterHookOK, fh.Reason)
	}
	if fh.WorkersHealthy != 1 || fh.WorkersTotal != 1 {
		t.Errorf("workers = %d/%d, want 1/1", fh.WorkersHealthy, fh.WorkersTotal)
	}
	if len(fh.Workers) != 1 || !fh.Workers[0].Healthy {
		t.Fatalf("worker projection wrong: %+v", fh.Workers)
	}
	if fh.VerdictCache.Status != VerdictCacheActive || fh.VerdictCache.ContentVersion != "abc123" {
		t.Errorf("verdict cache = %+v, want active under abc123", fh.VerdictCache)
	}
}

// TestDiagnostics_FilterHook_WedgedIsDistinctFromNeverStarted is the B5 core.
// Both states used to present as one `available:false` with no cause.
func TestDiagnostics_FilterHook_WedgedIsDistinctFromNeverStarted(t *testing.T) {
	// "Never started" uses the REAL production type: a ChildHook whose binary is
	// absent has never spawned, which is the state a box with a half-finished
	// install is in. No double can get this one wrong.
	neverStarted := apphook.NewChildHook(&apphook.ChildHookConfig{
		Name: "ai-compliance-detector", BinaryPath: "/nonexistent/detector", Timeout: time.Second,
	})
	// Mirrors what the real ChildHook publishes for a wedged unit: the process
	// cause is `write_timeout`, and because it is degraded it also cannot vouch
	// for its ruleset (contentVersionState → child_degraded). The `never started`
	// case above uses the real type and derives both for itself, which is what
	// proves this pairing is the production one and not a convenient fiction.
	wedged := &unitHook{st: apphook.Status{
		Healthy:              false,
		DegradedReason:       apphook.DegradeReasonWriteTimeout,
		ContentVersionReason: apphook.ContentVersionReasonChildDegraded,
		Version:              "detector/1.2.0",
		RestartCount:         3,
	}}

	cases := []struct {
		name       string
		hook       apphook.Hook
		wantReason string
	}{
		{"never started", neverStarted, apphook.DegradeReasonNotStarted},
		{"wedged mid-write", wedged, apphook.DegradeReasonWriteTimeout},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{filterHook: tc.hook}
			p.SetFilterCacheEnabled(true, 5)
			fh := readFilterHookDiagnostics(t, p).FilterHook

			if fh.Status != FilterHookDegraded {
				t.Errorf("status = %q, want %q", fh.Status, FilterHookDegraded)
			}
			if fh.WorkersHealthy != 0 || fh.WorkersTotal != 1 {
				t.Errorf("workers = %d/%d, want 0/1", fh.WorkersHealthy, fh.WorkersTotal)
			}
			if len(fh.Workers) != 1 {
				t.Fatalf("want one worker, got %+v", fh.Workers)
			}
			got := fh.Workers[0].DegradedReason
			if got != tc.wantReason {
				t.Errorf("degraded_reason = %q, want %q — without it a reader cannot pick a remedy",
					got, tc.wantReason)
			}
			seen[got] = true
			// A degraded child cannot vouch for its ruleset, so caching is off too.
			if fh.VerdictCache.Status != VerdictCacheSuspended {
				t.Errorf("verdict cache = %q, want %q", fh.VerdictCache.Status, VerdictCacheSuspended)
			}
			if fh.VerdictCache.Cause != apphook.ContentVersionReasonChildDegraded {
				t.Errorf("verdict cache cause = %q, want %q", fh.VerdictCache.Cause, apphook.ContentVersionReasonChildDegraded)
			}
		})
	}
	if len(seen) != 2 {
		t.Fatalf("the two failure modes collapsed to one externally visible reason %v — "+
			"that IS the bug (B5): the operator cannot tell a wedge from a missing spawn", seen)
	}
}

// TestDiagnostics_FilterHook_PartialPoolIsNotReportedHealthy is THE core
// judgment of this change.
//
// Measured during review: a 2-worker pool with one worker down reported
// Status().Healthy = true and "1/2 workers healthy", while 10 Detect calls
// produced 5 fail-opens. Round-robin dispatch has no health check (review
// finding B39, still open), so half the traffic really is forwarded
// un-inspected. A health block that renders that as `ok` is a false green and
// worse than no block at all.
func TestDiagnostics_FilterHook_PartialPoolIsNotReportedHealthy(t *testing.T) {
	dead := &unitHook{st: apphook.Status{
		Healthy: false, DegradedReason: apphook.DegradeReasonWriteTimeout,
		ContentVersionReason: apphook.ContentVersionReasonChildDegraded, RestartCount: 2,
	}}
	pool := &poolHook{units: []*unitHook{healthyUnit("packs-v1"), dead}}
	p := &Proxy{filterHook: pool}
	p.SetFilterCacheEnabled(true, 5)

	// The dispatch-facing aggregate still says keep-serving. That is correct and
	// must not change — it is the reason the health block cannot be derived from it.
	if !pool.Status().Healthy {
		t.Fatal("arrange: the aggregate must still be 'keep serving' for this to be the false-green shape")
	}

	fh := readFilterHookDiagnostics(t, p).FilterHook
	if fh.Status == FilterHookOK {
		t.Fatal("FALSE GREEN: a pool with a dead worker reported `ok`. The operator provisioned M " +
			"processes and is running on fewer; the survivors absorb the dead one's share and one " +
			"more failure ends inspection entirely. (Until the 2026-08-14 B39 data-plane fix this " +
			"was worse still: dispatch included the dead worker, so ≈1/M of all content was " +
			"forwarded to the upstream LLM un-inspected.)")
	}
	if fh.Status != FilterHookPartial {
		t.Errorf("status = %q, want %q", fh.Status, FilterHookPartial)
	}
	if fh.WorkersHealthy != 1 || fh.WorkersTotal != 2 {
		t.Errorf("workers = %d/%d, want 1/2", fh.WorkersHealthy, fh.WorkersTotal)
	}
	// Naming WHICH worker and WHY is what makes the row actionable.
	if fh.Workers[1].DegradedReason != apphook.DegradeReasonWriteTimeout {
		t.Errorf("the dead worker's cause was lost: %+v", fh.Workers[1])
	}
	if fh.Workers[1].Index != 1 {
		t.Errorf("worker index must be the dispatch position: %+v", fh.Workers[1])
	}
	// The reason must state the CONSEQUENCE, not just the count — it is the one
	// sentence `ak doctor` renders verbatim (see commands_project.rs; doctor no
	// longer describes dispatch in its own words, precisely because the two
	// drifted when the data plane changed on 2026-08-14).
	if !strings.Contains(fh.Reason, "Dispatch skips the unfit units") {
		t.Errorf("the reason must say what a partial pool now costs — dispatch skips unfit units, "+
			"so what is lost is headroom, not coverage: %q", fh.Reason)
	}
	if strings.Contains(fh.Reason, "un-inspected") {
		t.Errorf("stale consequence: `partial` no longer means content goes un-inspected. Every "+
			"surface renders this sentence verbatim, so leaving it would tell operators to chase "+
			"a coverage hole that does not exist: %q", fh.Reason)
	}
	// A degraded worker cannot contribute cacheable verdicts, but it also cannot
	// poison the cache — the survivor's token still keys it.
	if fh.VerdictCache.Status != VerdictCacheActive {
		t.Errorf("a degraded worker must not suspend caching pool-wide: %+v", fh.VerdictCache)
	}
}

// No filter installed is the common Personal default, not a fault. It must be
// legible as such — a health block that screams on every un-enabled install
// trains operators to ignore it.
func TestDiagnostics_FilterHook_NoHookIsInactiveNotDegraded(t *testing.T) {
	fh := readFilterHookDiagnostics(t, &Proxy{}).FilterHook
	if fh.Status != FilterHookInactive {
		t.Errorf("status = %q, want %q", fh.Status, FilterHookInactive)
	}
	if fh.WorkersTotal != 0 || len(fh.Workers) != 0 {
		t.Errorf("no hook means no units: %+v", fh)
	}
	if fh.VerdictCache.Status != VerdictCacheDisabled {
		t.Errorf("verdict cache = %q, want %q", fh.VerdictCache.Status, VerdictCacheDisabled)
	}
}

// The wire contract itself: field names and their presence. A Go-struct-only
// assertion would stay green if a json tag were dropped, and a dropped tag is
// precisely how apphook.Status became unreadable in the first place.
func TestDiagnostics_FilterHook_WireFieldNames(t *testing.T) {
	p := &Proxy{filterHook: &poolHook{units: []*unitHook{
		healthyUnit("packs-v1"),
		{st: apphook.Status{DegradedReason: apphook.DegradeReasonWriteTimeout, RestartCount: 7}},
	}}}
	p.SetFilterCacheEnabled(true, 5)

	block := rawFilterHookBlock(t, p)
	for _, key := range []string{"status", "reason", "name", "workers_healthy", "workers_total", "workers", "verdict_cache"} {
		if _, ok := block[key]; !ok {
			t.Errorf("filter_hook.%s missing from the wire: %v", key, block)
		}
	}
	workers, ok := block["workers"].([]any)
	if !ok || len(workers) != 2 {
		t.Fatalf("filter_hook.workers must be an array of every unit: %v", block["workers"])
	}
	w1, _ := workers[1].(map[string]any)
	for _, key := range []string{"index", "healthy", "degraded_reason", "restart_count"} {
		if _, ok := w1[key]; !ok {
			t.Errorf("filter_hook.workers[1].%s missing from the wire: %v", key, w1)
		}
	}
	// `omitempty` on the healthy worker keeps the payload honest: an absent
	// degraded_reason means "no cause", never "cause unknown".
	w0, _ := workers[0].(map[string]any)
	if _, present := w0["degraded_reason"]; present {
		t.Errorf("a healthy worker must not carry a degraded_reason: %v", w0)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The old-detector state (B6): visible on the endpoint AND logged, once
// ─────────────────────────────────────────────────────────────────────────────

// A detector too old to answer op=ListPacks answers Detect fine, so it is
// HEALTHY — and the proxy still switches its verdict cache off, on purpose. The
// endpoint has to say so, name the cause, and point at the remedy; otherwise the
// only symptom an operator ever sees is "the proxy got slower".
func TestDiagnostics_FilterHook_OldDetectorSuspendsCacheWithAnUpgradeRemedy(t *testing.T) {
	old := &unitHook{st: apphook.Status{
		Healthy:              true,
		Version:              "detector/1.0.0",
		ContentVersionReason: apphook.ContentVersionReasonUnsupported,
	}}
	p := &Proxy{filterHook: old}
	p.SetFilterCacheEnabled(true, 5)

	fh := readFilterHookDiagnostics(t, p).FilterHook
	if fh.Status != FilterHookOK {
		t.Errorf("an old detector is still ANSWERING — status = %q, want %q", fh.Status, FilterHookOK)
	}
	if fh.VerdictCache.Status != VerdictCacheSuspended {
		t.Fatalf("verdict cache = %q, want %q — the 96%%→0 hit-rate cliff must be readable",
			fh.VerdictCache.Status, VerdictCacheSuspended)
	}
	if fh.VerdictCache.Cause != apphook.ContentVersionReasonUnsupported {
		t.Errorf("cause = %q, want %q — restart and upgrade are different remedies",
			fh.VerdictCache.Cause, apphook.ContentVersionReasonUnsupported)
	}
	if !strings.Contains(fh.VerdictCache.Reason, "Upgrade") {
		t.Errorf("the reason must carry the next action, not just the state: %q", fh.VerdictCache.Reason)
	}
	if fh.Workers[0].ContentVersionReason != apphook.ContentVersionReasonUnsupported {
		t.Errorf("the per-unit cause must survive: %+v", fh.Workers[0])
	}
}

// When units are blind for DIFFERENT reasons, the reported cause must be the one
// that never self-heals — telling an operator to wait for a poll that will never
// arrive is worse than saying nothing.
func TestDiagnostics_VerdictCacheCause_UpgradeWinsOverTransientCauses(t *testing.T) {
	pending := &unitHook{st: apphook.Status{Healthy: true, ContentVersionReason: apphook.ContentVersionReasonPollPending}}
	tooOld := &unitHook{st: apphook.Status{Healthy: true, ContentVersionReason: apphook.ContentVersionReasonUnsupported}}
	p := &Proxy{filterHook: &poolHook{units: []*unitHook{pending, tooOld}}}
	p.SetFilterCacheEnabled(true, 5)

	got := readFilterHookDiagnostics(t, p).FilterHook.VerdictCache.Cause
	if got != apphook.ContentVersionReasonUnsupported {
		t.Errorf("cause = %q, want %q (the only cause with no self-healing path)",
			got, apphook.ContentVersionReasonUnsupported)
	}
}

// The cache being off because it was never turned on is a different fact from
// the cache being switched off at runtime. Collapsing them would let a
// deliberately cache-less deployment read as a broken one.
func TestDiagnostics_VerdictCache_DisabledIsNotSuspended(t *testing.T) {
	p := &Proxy{filterHook: healthyUnit("packs-v1")} // no SetFilterCacheEnabled
	vc := readFilterHookDiagnostics(t, p).FilterHook.VerdictCache
	if vc.Status != VerdictCacheDisabled {
		t.Errorf("status = %q, want %q", vc.Status, VerdictCacheDisabled)
	}
	if vc.Cause != "" {
		t.Errorf("a cache that was never enabled has no fault cause: %q", vc.Cause)
	}
}

// TestDiagnostics_VerdictCacheSuspension_WarnsOncePerTransition drives the REAL
// dispatcher (applyInboundFilter), not the logging helper in isolation.
//
// The rate limit is part of the contract, not an optimisation: an un-upgraded
// detector never starts answering op=ListPacks, so an unlatched line would emit
// at request rate for the life of the deployment and bury the signal it exists
// to raise. Same 「只记状态转变」 posture as the 16 KiB truncation aggregate.
func TestDiagnostics_VerdictCacheSuspension_WarnsOncePerTransition(t *testing.T) {
	blind := &unitHook{st: apphook.Status{
		Healthy: true, ContentVersionReason: apphook.ContentVersionReasonUnsupported,
	}}
	p := &Proxy{filterHook: blind}
	p.SetFilterCacheEnabled(true, 5)

	var buf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	const body = `{"messages":[{"role":"user","content":"hello world"}]}`

	for i := 0; i < 5; i++ {
		p.applyInboundFilter(httptest.NewRecorder(), newReq(body), "m", "personal", "", "", "", "", "", logger)
	}
	suspended := strings.Count(buf.String(), observability.EventProxyFilterVerdictCacheSuspended)
	if suspended != 1 {
		t.Fatalf("verdict-cache suspension logged %d times over 5 requests, want exactly 1 — "+
			"this state persists, so an unlatched line would emit at request rate forever.\n%s",
			suspended, buf.String())
	}
	if !strings.Contains(buf.String(), apphook.ContentVersionReasonUnsupported) {
		t.Errorf("the WARN must carry the enumerated cause (restart vs upgrade): %s", buf.String())
	}

	// Recovery re-arms the latch and brackets the window, so an operator can see
	// when the cold-scan period ended rather than inferring it from silence.
	blind.st.ContentVersion = "packs-v2"
	blind.st.ContentVersionReason = ""
	buf.Reset()
	for i := 0; i < 3; i++ {
		p.applyInboundFilter(httptest.NewRecorder(), newReq(body), "m", "personal", "", "", "", "", "", logger)
	}
	if n := strings.Count(buf.String(), observability.EventProxyFilterVerdictCacheResumed); n != 1 {
		t.Errorf("resume logged %d times over 3 requests, want exactly 1: %s", n, buf.String())
	}

	// And the endpoint agrees with the log — one derivation, two surfaces.
	if got := readFilterHookDiagnostics(t, p).FilterHook.VerdictCache.Status; got != VerdictCacheActive {
		t.Errorf("endpoint = %q after recovery, want %q", got, VerdictCacheActive)
	}
}
