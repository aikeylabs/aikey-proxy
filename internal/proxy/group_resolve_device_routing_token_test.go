// group_resolve_device_routing_token_test.go — the worker's STRICT branch for a
// device-routing token: the control plane already decided which pool account
// this device belongs to and said so in the internal header, so this worker
// serves THAT account or refuses. It never picks another one, and it never
// retries on another one.
//
// What each fence answers (the question no unit test on the picker can):
//
//	does the header beat local HRW ranking?              → R-…-7.S1
//	is a cooled/window-blocked pinned account a 429
//	  with ZERO upstream requests and no switch?          → R-…-7.S1
//	is an upstream 429 passed through verbatim, exactly
//	  once, with no aikey error-source marker?            → R-…-7.S1
//	does the usage event still say route_source=team?     → R-…-7.S1
//	is a missing header a loud 503 + a counted WARN?      → R-…-7.S3
//	does that counter age out of its 24h window with no
//	  restart and no timer?                               → R-…-7.S3
//	do the three account states get three answers?        → R-…-7.S4
//	is the header an ACCOUNT id, not a credential id?     → R-…-7.S4
//	is a route whose kind never arrived refused rather
//	  than served on the seat path?                       → R-…-20.S2
//	is the X-Aikey-* namespace still absent upstream?     → RED LINE
//
// Requirement package: roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/
// (design §4b.3 内部头合约, §4b.8 节点能力闸, spec
// openspec/specs/device-routing-token-dispatch/spec.md).
//
// 能红 (how each fence goes red if the branch regresses) is noted per fence.
//
// Every "zero upstream" claim is COUNTED at the transport, never inferred from a
// status code, and every "no switch" claim reads the Authorization the transport
// actually received — a pool that answers 429 for the wrong reason would
// otherwise look identical.
package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

const (
	drtVKToken = "aikey_team_drtoken"
	drtVKID    = "vk-drt"
	drtGroupID = "grp-drt"
	drtSeatID  = "seat-drt"

	drtAccountA = "acc-drt-alpha"
	drtAccountB = "acc-drt-beta"

	drtPath = "/v1/messages"
)

// drtBody is a plain (non-streaming) Anthropic request: the pool's dialect
// gates accept it unchanged, so nothing but the strict branch can decide the
// outcome, and the usage event is recorded on the synchronous path where a
// fence can read it.
func drtBody() []byte {
	return []byte(`{"model":"claude-sonnet-4-5-20250929","messages":[]}`)
}

func drtTokenFor(accountID string) string { return "tok-" + accountID }

// drtCredFor keeps the credential id DELIBERATELY different from the account id.
// The internal header carries the ACCOUNT id (design §4b.3); a worker that
// matched on credential_id instead would pass every other fence in this file.
func drtCredFor(accountID string) string { return "cred-" + accountID }

// drtAccounts returns (pinned, other) where `pinned` is the account local HRW
// ranking would NOT choose. So "the pinned account served" can only be true
// because the header won — not because it happened to be rank-0.
func drtAccounts(t *testing.T) (pinned, other string) {
	t.Helper()
	order := rankOrder(drtSeatID, drtAccountA, drtAccountB)
	return order[1], order[0]
}

// ── fixtures ────────────────────────────────────────────────────────────────

type drtSeen struct {
	auth   string
	header http.Header
}

// drtTransport counts and records EVERY outbound request and can script one
// upstream status. Separate from the other recording transports in this package
// so widening it cannot change what their fences exercise.
type drtTransport struct {
	mu     sync.Mutex
	seen   []drtSeen
	status int
	header http.Header
	body   string
}

func (tr *drtTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.mu.Lock()
	tr.seen = append(tr.seen, drtSeen{auth: req.Header.Get("Authorization"), header: req.Header.Clone()})
	status, extra, body := tr.status, tr.header, tr.body
	tr.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	if body == "" {
		body = `{"id":"msg_1","type":"message","role":"assistant","content":[],` +
			`"usage":{"input_tokens":1,"output_tokens":1}}`
	}
	h := http.Header{"Content-Type": []string{"application/json"}}
	for k, v := range extra {
		h[k] = v
	}
	return &http.Response{
		StatusCode: status, Header: h,
		Body:    io.NopCloser(strings.NewReader(body)),
		Request: req,
	}, nil
}

func (tr *drtTransport) all() []drtSeen {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]drtSeen(nil), tr.seen...)
}

// dialed reports the accounts the transport was actually asked to serve, in
// order. Derived from the injected bearer, so it cannot be faked by a status.
func (tr *drtTransport) dialed() []string {
	out := []string{}
	for _, s := range tr.all() {
		token := strings.TrimPrefix(s.auth, "Bearer ")
		out = append(out, strings.TrimPrefix(token, "tok-"))
	}
	return out
}

type drtPool struct {
	p         *Proxy
	transport *drtTransport
	route     *vkeys.ResolvedRoute
	key       []byte
	walDir    string
	wal       *events.WALWriter
}

// drtMaterialOpt mutates one account's delivered material before it is encrypted.
type drtMaterialOpt func(map[string]*vkeys.GroupRuntimeAccount)

// newDRTPool builds a hermetic two-account pool. routeKind "" reproduces the
// row an OLD cluster daemon writes (the column exists, the value is empty).
func newDRTPool(t *testing.T, routeKind string, opts ...drtMaterialOpt) *drtPool {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	key := grKey()

	refs := []vkeys.GroupAccountRef{
		{AccountID: drtAccountA, ProviderCode: "anthropic", ProtocolType: "anthropic", CredentialID: drtCredFor(drtAccountA), Identity: drtAccountA + "@example.test"},
		{AccountID: drtAccountB, ProviderCode: "anthropic", ProtocolType: "anthropic", CredentialID: drtCredFor(drtAccountB), Identity: drtAccountB + "@example.test"},
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: drtVKID, Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team", RouteKind: routeKind,
		SeatID: drtSeatID, OauthGroupID: drtGroupID,
		GroupAccounts: mustJSON(t, refs),
	}
	pool := &drtPool{route: route, key: key}
	pool.setMaterial(t, opts...)

	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{drtVKToken: route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	transport := &drtTransport{}
	p.SetTransport(transport)
	pool.p, pool.transport = p, transport
	return pool
}

// setMaterial (re)writes the delivered group material in place — the same thing
// the material rail does between two requests, with no proxy restart.
func (f *drtPool) setMaterial(t *testing.T, opts ...drtMaterialOpt) {
	t.Helper()
	live := map[string]*vkeys.GroupRuntimeAccount{}
	for _, id := range []string{drtAccountA, drtAccountB} {
		live[id] = &vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account",
			ProviderCode:   "anthropic",
			ProtocolType:   "anthropic",
			CredentialID:   drtCredFor(id),
			Identity:       id + "@example.test",
			// ExternalID is required by the anthropic B2 guard; a pool account
			// without it is refused before the strict branch can be observed.
			ExternalID: "ext-" + id,
			ExpiresAt:  9_000_000_000,
		}
	}
	for _, opt := range opts {
		opt(live)
	}
	mat := map[string]vkeys.GroupRuntimeAccount{}
	for id, acc := range live {
		if acc == nil {
			continue // material for this account has not reached the worker
		}
		mat[id] = encMat(t, f.key, *acc, drtTokenFor(id))
	}
	f.route.GroupRuntime = mustJSON(t, mat)
}

// withWAL attaches a WAL so a fence can read the REPORTED wire event.
func (f *drtPool) withWAL(t *testing.T) *drtPool {
	t.Helper()
	f.walDir = t.TempDir()
	wal, err := events.NewWALWriter(f.walDir)
	if err != nil {
		t.Fatalf("NewWALWriter: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	f.wal = wal
	f.p.SetWAL(wal)
	f.p.SetReporter(nil, "proxy-drt", "test", "gen-drt", 0, "acc-drt")
	return f
}

// awaitWALEntry waits for the REPORTED wire event to land. reportUsage runs off
// the request goroutine, so reading the WAL right after the handler returns is a
// race — one that resolves as "no file", i.e. it would look like the strict
// branch never reported at all.
func (f *drtPool) awaitWALEntry(t *testing.T) walEntryEnvelope {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ents, _ := os.ReadDir(f.walDir)
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".jsonl") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(f.walDir, e.Name()))
			if err == nil && len(strings.TrimSpace(string(raw))) > 0 {
				_ = f.wal.Close()
				return readLastWALEntry(t, f.walDir)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy never appended a usage event to the WAL in %s", f.walDir)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// serve drives ONE request through the real handler chain. pinned == "" omits
// the internal header entirely (the old-ingress shape).
func (f *drtPool) serve(t *testing.T, pinned string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, drtPath, bytes.NewReader(drtBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+drtVKToken)
	if pinned != "" {
		req.Header.Set(headerRouteAccount, pinned)
	}
	w := httptest.NewRecorder()
	f.p.Handle(w, req)
	return w
}

// drtErrorBody is the client-visible error envelope (writeJSONErrorDetails).
type drtErrorBody struct {
	Error struct {
		Message           string `json:"message"`
		Type              string `json:"type"`
		Code              string `json:"code"`
		Reason            string `json:"reason"`
		RetryAt           int64  `json:"retry_at"`
		RetryAfterSeconds int    `json:"retry_after_seconds"`
	} `json:"error"`
}

func drtDecodeError(t *testing.T, w *httptest.ResponseRecorder) drtErrorBody {
	t.Helper()
	var body drtErrorBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body (%q): %v", w.Body.String(), err)
	}
	return body
}

// drtLogs points the default logger at a buffer for one test.
func drtLogs(t *testing.T) *codexRewriteLogBuffer {
	t.Helper()
	buf := &codexRewriteLogBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// drtClock is the injectable clock behind the 24h sliding window. The window
// must age out because time passed, never because a goroutine fired.
type drtClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *drtClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *drtClock) advance(d time.Duration) {
	c.mu.Lock()
	c.at = c.at.Add(d)
	c.mu.Unlock()
}

// drtResetStatus isolates the process-wide counters for one test and hands back
// the clock driving their window.
func drtResetStatus(t *testing.T) *drtClock {
	t.Helper()
	clock := &drtClock{at: time.Unix(1_700_000_000, 0).UTC()}
	resetDeviceRoutingStatusForTest(clock.Now)
	t.Cleanup(func() { resetDeviceRoutingStatusForTest(time.Now) })
	return clock
}

func drtAssertNoUpstream(t *testing.T, tr *drtTransport) {
	t.Helper()
	if dialed := tr.dialed(); len(dialed) != 0 {
		t.Fatalf("the upstream was dialed %d time(s) (%v) — a refusal that already spent an account's quota is not a refusal", len(dialed), dialed)
	}
}

func drtAssertAikeySource(t *testing.T, w *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	if got := w.Header().Get(HeaderAikeyErrorSource); got != wantCode {
		t.Fatalf("%s = %q, want %q — an aikey-generated refusal must be distinguishable from an upstream one", HeaderAikeyErrorSource, got, wantCode)
	}
}

// ── R-device-routing-token-dispatch-7.S1 · the named account serves ─────────

// TestDeviceRoutingStrict_PinnedAccountServes proves the header is authoritative:
// the pinned account is deliberately the one local ranking would NOT pick, so a
// worker that ignored the header would serve the other account and go red here.
//
// 能红: drop `override = pinned` in the strict branch → the ranked walk serves
// `other` → this fence fails naming both accounts.
//
// spec: R-device-routing-token-dispatch-7.S1 绑定账号额度用完 —— 恢复后由 X 服务
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/device-routing-token-dispatch/spec.md
func TestDeviceRoutingStrict_PinnedAccountServes(t *testing.T) {
	drtResetStatus(t)
	pinned, other := drtAccounts(t)
	pool := newDRTPool(t, routeKindDeviceRoutingToken)

	if w := pool.serve(t, pinned); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	dialed := pool.transport.dialed()
	if len(dialed) != 1 || dialed[0] != pinned {
		t.Fatalf("upstream dialed %v, want exactly [%s] — local HRW would have picked %s, the header must win", dialed, pinned, other)
	}
}

// TestDeviceRoutingStrict_CoolingIs429ZeroUpstreamNoSwitch is the pre-check half
// of R-…-7.S1: the pinned account is cooling, so the answer is a 429 that names
// the device-routing code, carries a retry horizon, and spends NO upstream quota
// — and the healthy sibling is never touched.
//
// 能红: let the strict branch fall through to the ranked candidates when the
// pinned account is cooling → the sibling serves, the status is 200 → red.
//
// spec: R-device-routing-token-dispatch-7.S1
func TestDeviceRoutingStrict_CoolingIs429ZeroUpstreamNoSwitch(t *testing.T) {
	drtResetStatus(t)
	pinned, other := drtAccounts(t)
	pool := newDRTPool(t, routeKindDeviceRoutingToken)
	// Drive the cooldown store from a fixed clock so "recovered" is a clock
	// move, not a sleep.
	t0 := time.Now()
	pool.p.poolCooldown.now = func() time.Time { return t0 }
	until := t0.Add(90 * time.Second)
	pool.p.poolCooldown.markWithState(pinned, until, PoolAccountRouteState{
		Status: poolRouteRateLimited, RetryAt: until.Unix(),
	})

	w := pool.serve(t, pinned)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body=%s)", w.Code, w.Body.String())
	}
	drtAssertNoUpstream(t, pool.transport)
	drtAssertAikeySource(t, w, observability.ErrCodeDeviceRoutingTokenAccountExhausted)
	if got := w.Header().Get("Retry-After"); got == "" {
		t.Fatal("a pre-check 429 must carry Retry-After — without it the client has no recovery horizon")
	}
	body := drtDecodeError(t, w)
	if body.Error.Code != observability.ErrCodeDeviceRoutingTokenAccountExhausted {
		t.Fatalf("error.code = %q, want %q", body.Error.Code, observability.ErrCodeDeviceRoutingTokenAccountExhausted)
	}
	if body.Error.RetryAt != until.Unix() {
		t.Fatalf("retry_at = %d, want the authoritative cooldown deadline %d", body.Error.RetryAt, until.Unix())
	}
	if pool.p.poolCooldown.skipSet()[other] {
		t.Fatalf("the sibling %s must stay eligible — the refusal is about the PINNED account only", other)
	}

	// Recovery: once the cooldown lapses the SAME account serves again — the
	// device never moved, so nothing has to be rebound.
	pool.p.poolCooldown.now = func() time.Time { return t0.Add(2 * time.Minute) }
	if w2 := pool.serve(t, pinned); w2.Code != http.StatusOK {
		t.Fatalf("after recovery status = %d, want 200 (body=%s)", w2.Code, w2.Body.String())
	}
	if dialed := pool.transport.dialed(); len(dialed) != 1 || dialed[0] != pinned {
		t.Fatalf("after recovery upstream dialed %v, want exactly [%s]", dialed, pinned)
	}
}

// TestDeviceRoutingStrict_Upstream429PassedThroughOnce is 策略 C (用户 2026-09-20):
// once the request HAS gone out, an upstream 429 is the answer. No second
// account, exactly one upstream request, and NO X-Aikey-Error-Source — that
// header is how a client tells "aikey refused" from "the provider refused"
// (2026-06-05-aikey-vs-upstream-error-distinguishable).
//
// 能红: remove the strict no-retry guard → the failover loop tries the sibling →
// two upstream calls → red on the count.
//
// spec: R-device-routing-token-dispatch-7.S1
func TestDeviceRoutingStrict_Upstream429PassedThroughOnce(t *testing.T) {
	drtResetStatus(t)
	pinned, other := drtAccounts(t)
	pool := newDRTPool(t, routeKindDeviceRoutingToken)
	// Retry-After makes it a rate-limit 429 WITH evidence — i.e. exactly the
	// shape the account-axis failover treats as "try another account".
	pool.transport.status = http.StatusTooManyRequests
	pool.transport.header = http.Header{"Retry-After": []string{"42"}}
	pool.transport.body = `{"type":"error","error":{"type":"rate_limit_error","message":"upstream says slow down"}}`

	w := pool.serve(t, pinned)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want the upstream's own 429 (body=%s)", w.Code, w.Body.String())
	}
	dialed := pool.transport.dialed()
	if len(dialed) != 1 || dialed[0] != pinned {
		t.Fatalf("upstream dialed %v, want exactly [%s] — a device-routing token must never fail over to %s", dialed, pinned, other)
	}
	if got := w.Header().Get(HeaderAikeyErrorSource); got != "" {
		t.Fatalf("%s = %q on a PASSED-THROUGH upstream 429 — that marker means aikey generated it", HeaderAikeyErrorSource, got)
	}
	if !strings.Contains(w.Body.String(), "upstream says slow down") {
		t.Fatalf("body = %s, want the upstream envelope verbatim", w.Body.String())
	}
}

// TestDeviceRoutingStrict_UsageEventRouteSourceIsTeam keeps the usage WAL key
// unchanged. route_source is a billing/attribution dimension: a device-routing
// request is still a TEAM route, so flipping it would split one pool's history
// across two lanes.
//
// 能红: stamp any other route_source on the strict branch → red.
//
// spec: R-device-routing-token-dispatch-7.S1（`route_source` 保持 "team"）
func TestDeviceRoutingStrict_UsageEventRouteSourceIsTeam(t *testing.T) {
	drtResetStatus(t)
	pinned, _ := drtAccounts(t)
	pool := newDRTPool(t, routeKindDeviceRoutingToken).withWAL(t)

	if w := pool.serve(t, pinned); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	entry := pool.awaitWALEntry(t)
	if entry.EventJSON.RouteSource != "team" {
		t.Fatalf("wire route_source = %q, want \"team\" — the strict branch must not re-label the lane", entry.EventJSON.RouteSource)
	}
	if entry.EventJSON.AccountID != pinned {
		t.Fatalf("wire account_id = %q, want the pinned account %q", entry.EventJSON.AccountID, pinned)
	}
}

// ── R-device-routing-token-dispatch-7.S3 · the decision is missing ─────────

// TestDeviceRoutingStrict_MissingHeaderIsNoDecision is the rolling-upgrade
// window: an old ingress forwards the request without the account decision.
// Fail closed — picking locally would put this device on a second account and
// re-link exactly what the feature exists to separate.
//
// 能红: fall back to the local pick when the header is absent → 200 → red.
//
// spec: R-device-routing-token-dispatch-7.S3 决定缺失（老入口）
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/device-routing-token-dispatch/spec.md
func TestDeviceRoutingStrict_MissingHeaderIsNoDecision(t *testing.T) {
	drtResetStatus(t)
	logs := drtLogs(t)
	pool := newDRTPool(t, routeKindDeviceRoutingToken)

	w := pool.serve(t, "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body=%s)", w.Code, w.Body.String())
	}
	drtAssertNoUpstream(t, pool.transport)
	drtAssertAikeySource(t, w, observability.ErrCodeDeviceRoutingTokenNoDecision)
	if got := w.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want \"1\"", got)
	}
	if body := drtDecodeError(t, w); body.Error.Code != observability.ErrCodeDeviceRoutingTokenNoDecision {
		t.Fatalf("error.code = %q, want %q", body.Error.Code, observability.ErrCodeDeviceRoutingTokenNoDecision)
	}
	if got := DeviceRoutingTokenSnapshot().DecisionMissing24h; got != 1 {
		t.Fatalf("decision_missing_24h = %d, want 1 — the operator has no other way to see an old ingress", got)
	}
	if !strings.Contains(logs.String(), observability.EventProxyDeviceRoutingDecisionMissing) {
		t.Fatalf("no %s WARN was logged; log=%s", observability.EventProxyDeviceRoutingDecisionMissing, logs.String())
	}
	if !strings.Contains(logs.String(), `"level":"WARN"`) {
		t.Fatalf("the decision-missing log is not at WARN; log=%s", logs.String())
	}
}

// TestDeviceRoutingStrict_DecisionMissingExpiresAfter24h: the counter is a
// SLIDING window, not a lifetime total. A total that can only grow means the
// WARN never clears once an old ingress has been seen even for a second, so an
// operator learns to ignore it. Aging out must need neither a restart nor a
// timer — only the clock moving.
//
// 能红: make the counter a monotonic total → still 1 after 25h → red.
//
// spec: R-device-routing-token-dispatch-7.S3（滑动窗口，不是只增不减的累计数）
func TestDeviceRoutingStrict_DecisionMissingExpiresAfter24h(t *testing.T) {
	clock := drtResetStatus(t)
	pool := newDRTPool(t, routeKindDeviceRoutingToken)

	if w := pool.serve(t, ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if got := DeviceRoutingTokenSnapshot().DecisionMissing24h; got != 1 {
		t.Fatalf("decision_missing_24h = %d, want 1", got)
	}

	// Still inside the window: the signal must NOT disappear early.
	clock.advance(23 * time.Hour)
	if got := DeviceRoutingTokenSnapshot().DecisionMissing24h; got != 1 {
		t.Fatalf("decision_missing_24h = %d after 23h, want 1 — the window closed too early", got)
	}

	// Past the window with no new occurrence: back to zero, same process.
	clock.advance(2 * time.Hour)
	snap := DeviceRoutingTokenSnapshot()
	if snap.DecisionMissing24h != 0 {
		t.Fatalf("decision_missing_24h = %d after 25h, want 0 — the WARN would never clear", snap.DecisionMissing24h)
	}
	// The counter must still be REPORTED as zero: a field that vanishes at zero
	// is indistinguishable from a build that cannot report it at all.
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if !strings.Contains(string(raw), `"decision_missing_24h":0`) {
		t.Fatalf("snapshot JSON = %s, want an explicit decision_missing_24h:0", raw)
	}

	// And the pool still serves: nothing was quarantined by the expired signal.
	pinned, _ := drtAccounts(t)
	if w := pool.serve(t, pinned); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 after the window aged out (body=%s)", w.Code, w.Body.String())
	}
}

// ── R-device-routing-token-dispatch-7.S4 · three states, three answers ─────

// TestDeviceRoutingStrict_ThreeAccountStates is the anti-mislabel fence: the
// 429 code means quota/cooldown/window and NOTHING else. Material that has not
// synced and a credential that is unusable are 503s with their own reason, so
// an operator is not sent to look at quota when the real fact is a sync lag or a
// revoked token.
//
// 能红: classify by "the picker returned someone else" instead of by the pinned
// account's own state → every case collapses to one code → red.
//
// spec: R-device-routing-token-dispatch-7.S4 材料未到或凭证失效不报成额度用完
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/device-routing-token-dispatch/spec.md
func TestDeviceRoutingStrict_ThreeAccountStates(t *testing.T) {
	pinned, other := drtAccounts(t)

	cases := []struct {
		name       string
		opt        drtMaterialOpt
		revoke     bool
		cool       bool
		wantStatus int
		wantCode   string
		wantReason string
	}{
		{
			name:       "material has not reached this worker",
			opt:        func(m map[string]*vkeys.GroupRuntimeAccount) { m[pinned] = nil },
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   observability.ErrCodeDeviceRoutingTokenAccountNotReady,
			wantReason: string(vkeys.OverrideMaterialNotReady),
		},
		{
			name: "account-level credential needs a login",
			opt: func(m map[string]*vkeys.GroupRuntimeAccount) {
				m[pinned].NeedsLogin = true
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   observability.ErrCodeDeviceRoutingTokenAccountNotReady,
			wantReason: string(vkeys.OverrideCredentialUnusable),
		},
		{
			name: "access token expired and cannot be refreshed here",
			opt: func(m map[string]*vkeys.GroupRuntimeAccount) {
				m[pinned].ExpiresAt = time.Now().Add(-time.Hour).Unix()
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   observability.ErrCodeDeviceRoutingTokenAccountNotReady,
			wantReason: string(vkeys.OverrideCredentialUnusable),
		},
		{
			// 情形丙: this worker already learned upstream rejected THIS token,
			// while the delivered material still looks perfectly healthy.
			name:       "locally remembered hard revoke while the material still looks fine",
			revoke:     true,
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   observability.ErrCodeDeviceRoutingTokenAccountNotReady,
			wantReason: string(vkeys.OverrideCredentialUnusable),
		},
		{
			// Both at once: waiting out a cooldown cannot fix a rejected token.
			name:       "cooling AND hard-revoked reports the credential",
			revoke:     true,
			cool:       true,
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   observability.ErrCodeDeviceRoutingTokenAccountNotReady,
			wantReason: string(vkeys.OverrideCredentialUnusable),
		},
		{
			name: "quota window exhausted",
			opt: func(m map[string]*vkeys.GroupRuntimeAccount) {
				reset := time.Now().Add(time.Hour).Unix()
				m[pinned].WindowStatus = "exhausted_current_window"
				m[pinned].WindowResetAt = &reset
			},
			wantStatus: http.StatusTooManyRequests,
			wantCode:   observability.ErrCodeDeviceRoutingTokenAccountExhausted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drtResetStatus(t)
			var opts []drtMaterialOpt
			if tc.opt != nil {
				opts = append(opts, tc.opt)
			}
			pool := newDRTPool(t, routeKindDeviceRoutingToken, opts...)
			if tc.revoke {
				pool.p.poolCooldown.markAuthFailedToken(drtGroupID, drtSeatID, pinned, oauthTokenFingerprint(drtTokenFor(pinned)))
			}
			if tc.cool {
				until := time.Now().Add(time.Minute)
				pool.p.poolCooldown.markWithState(pinned, until, PoolAccountRouteState{Status: poolRouteRateLimited, RetryAt: until.Unix()})
			}

			w := pool.serve(t, pinned)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", w.Code, tc.wantStatus, w.Body.String())
			}
			drtAssertNoUpstream(t, pool.transport)
			body := drtDecodeError(t, w)
			if body.Error.Code != tc.wantCode {
				t.Fatalf("error.code = %q, want %q (body=%s)", body.Error.Code, tc.wantCode, w.Body.String())
			}
			if body.Error.Reason != tc.wantReason {
				t.Fatalf("error.reason = %q, want %q", body.Error.Reason, tc.wantReason)
			}
			if tc.wantStatus == http.StatusServiceUnavailable {
				if got := w.Header().Get("Retry-After"); got != "2" {
					t.Fatalf("Retry-After = %q, want \"2\"", got)
				}
			}
			// The healthy sibling must be untouched: hit count 0 is the whole
			// point of the strict branch.
			for _, dialed := range pool.transport.dialed() {
				if dialed == other {
					t.Fatalf("the sibling %s served the request — the device would have moved accounts", other)
				}
			}
		})
	}
}

// TestDeviceRoutingStrict_HeaderMustBeAccountIDNotCredentialID: the header
// carries the ACCOUNT id (design §4b.3). The two ids differ in this fixture on
// purpose — a worker matching on credential_id would otherwise pass every other
// fence here and then fail in production, where the control plane sends the
// account id.
//
// 能红: match the header against GroupAccountRef.CredentialID → the two
// sub-cases swap answers → red.
//
// spec: R-device-routing-token-dispatch-7.S4
func TestDeviceRoutingStrict_HeaderMustBeAccountIDNotCredentialID(t *testing.T) {
	pinned, _ := drtAccounts(t)
	if drtCredFor(pinned) == pinned {
		t.Fatal("fixture bug: the credential id and the account id must differ for this fence to mean anything")
	}

	t.Run("credential id is refused", func(t *testing.T) {
		drtResetStatus(t)
		pool := newDRTPool(t, routeKindDeviceRoutingToken)
		w := pool.serve(t, drtCredFor(pinned))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503 (body=%s)", w.Code, w.Body.String())
		}
		drtAssertNoUpstream(t, pool.transport)
		body := drtDecodeError(t, w)
		if body.Error.Code != observability.ErrCodeDeviceRoutingTokenAccountNotReady {
			t.Fatalf("error.code = %q, want %q", body.Error.Code, observability.ErrCodeDeviceRoutingTokenAccountNotReady)
		}
		if body.Error.Reason != string(vkeys.OverrideMaterialNotReady) {
			t.Fatalf("error.reason = %q, want %q", body.Error.Reason, vkeys.OverrideMaterialNotReady)
		}
	})

	t.Run("account id serves", func(t *testing.T) {
		drtResetStatus(t)
		pool := newDRTPool(t, routeKindDeviceRoutingToken)
		if w := pool.serve(t, pinned); w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
		}
		if dialed := pool.transport.dialed(); len(dialed) != 1 || dialed[0] != pinned {
			t.Fatalf("upstream dialed %v, want exactly [%s]", dialed, pinned)
		}
	})
}

// ── R-device-routing-token-dispatch-20.S2 · the route kind never arrived ───

// TestDeviceRoutingStrict_RouteKindMissing is the old-daemon trap: the node
// vault HAS the route_kind column (it survived the downgrade) but the rolled-back
// daemon does not write it, so the row is blank. Serving that request on the seat
// path is the one outcome that must never happen — it would pick an account
// locally and silently re-link the devices.
//
// The counters are the operator's only window into this: _active is what alerts
// (it must fall back to 0 by itself), _total is lifetime diagnosis.
//
// 能红: remove the per-request self-check → the request is served on the seat
// path, status 200, _active stays 0 → red three ways.
//
// spec: R-device-routing-token-dispatch-20.S2 新 proxy + 旧守护进程 + 已迁移的
// vault —— 拒绝，而不是当普通令牌服务
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/device-routing-token-dispatch/spec.md
func TestDeviceRoutingStrict_RouteKindMissing(t *testing.T) {
	drtResetStatus(t)
	logs := drtLogs(t)
	pinned, _ := drtAccounts(t)
	// routeKind "" = the blank column an old daemon leaves behind.
	pool := newDRTPool(t, "")

	w := pool.serve(t, pinned)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body=%s)", w.Code, w.Body.String())
	}
	drtAssertNoUpstream(t, pool.transport)
	drtAssertAikeySource(t, w, observability.ErrCodeDeviceRoutingTokenNodeUnsupported)
	body := drtDecodeError(t, w)
	if body.Error.Code != observability.ErrCodeDeviceRoutingTokenNodeUnsupported {
		t.Fatalf("error.code = %q, want %q", body.Error.Code, observability.ErrCodeDeviceRoutingTokenNodeUnsupported)
	}
	if body.Error.Reason != deviceRoutingReasonRouteKindMissing {
		t.Fatalf("error.reason = %q, want %q", body.Error.Reason, deviceRoutingReasonRouteKindMissing)
	}
	if got := w.Header().Get("Retry-After"); got == "" {
		t.Fatal("NODE_UNSUPPORTED must carry Retry-After — the node is expected to be upgraded, not written off")
	}
	snap := DeviceRoutingTokenSnapshot()
	if snap.RouteKindMissingActive != 1 || snap.RouteKindMissingTotal != 1 {
		t.Fatalf("route_kind_missing_active/_total = %d/%d, want 1/1", snap.RouteKindMissingActive, snap.RouteKindMissingTotal)
	}
	if !strings.Contains(logs.String(), observability.EventProxyDeviceRoutingRouteKindMissing) {
		t.Fatalf("no %s log was written; log=%s", observability.EventProxyDeviceRoutingRouteKindMissing, logs.String())
	}
	if !strings.Contains(logs.String(), `"level":"ERROR"`) {
		t.Fatalf("route_kind_missing must be louder than a WARN (CRIT signal); log=%s", logs.String())
	}

	// A repeat occurrence must not inflate _active (it is a SET of tokens), only
	// _total.
	if w2 := pool.serve(t, pinned); w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("second attempt status = %d, want 503", w2.Code)
	}
	if snap := DeviceRoutingTokenSnapshot(); snap.RouteKindMissingActive != 1 || snap.RouteKindMissingTotal != 2 {
		t.Fatalf("after a repeat: active/total = %d/%d, want 1/2", snap.RouteKindMissingActive, snap.RouteKindMissingTotal)
	}

	t.Run("resync clears active without restarting the proxy", func(t *testing.T) {
		// The upgraded daemon re-syncs: the same in-memory route now carries the
		// kind. No new Proxy, no reload — exactly the production self-heal.
		pool.route.RouteKind = routeKindDeviceRoutingToken
		if w := pool.serve(t, pinned); w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 after the resync (body=%s)", w.Code, w.Body.String())
		}
		snap := DeviceRoutingTokenSnapshot()
		if snap.RouteKindMissingActive != 0 {
			t.Fatalf("route_kind_missing_active = %d, want 0 — the CRIT must clear itself", snap.RouteKindMissingActive)
		}
		if snap.RouteKindMissingTotal != 2 {
			t.Fatalf("route_kind_missing_total = %d, want the lifetime count 2 (it never decreases)", snap.RouteKindMissingTotal)
		}
	})

	t.Run("a route reload alone clears active when no request follows", func(t *testing.T) {
		drtResetStatus(t)
		pool := newDRTPool(t, "")
		if w := pool.serve(t, pinned); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", w.Code)
		}
		if got := DeviceRoutingTokenSnapshot().RouteKindMissingActive; got != 1 {
			t.Fatalf("route_kind_missing_active = %d, want 1", got)
		}

		// Reload #1 still carries the blank kind → the token stays listed.
		ReconcileDeviceRoutingRouteKind(map[string]*vkeys.ResolvedRoute{drtVKToken: pool.route})
		if got := DeviceRoutingTokenSnapshot().RouteKindMissingActive; got != 1 {
			t.Fatalf("route_kind_missing_active = %d after a reload that changed nothing, want 1", got)
		}

		// Reload #2 brings the kind → cleared, with no request in between.
		fixed := *pool.route
		fixed.RouteKind = routeKindDeviceRoutingToken
		ReconcileDeviceRoutingRouteKind(map[string]*vkeys.ResolvedRoute{drtVKToken: &fixed})
		if got := DeviceRoutingTokenSnapshot().RouteKindMissingActive; got != 0 {
			t.Fatalf("route_kind_missing_active = %d after the reload delivered the kind, want 0", got)
		}
	})

	t.Run("a deleted token also clears active", func(t *testing.T) {
		drtResetStatus(t)
		pool := newDRTPool(t, "")
		if w := pool.serve(t, pinned); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", w.Code)
		}
		ReconcileDeviceRoutingRouteKind(map[string]*vkeys.ResolvedRoute{})
		if got := DeviceRoutingTokenSnapshot().RouteKindMissingActive; got != 0 {
			t.Fatalf("route_kind_missing_active = %d after the token vanished from the registry, want 0", got)
		}
	})
}

// TestDeviceRoutingStrict_SeatVKWithHeaderIsRefused is the BUT NOT of
// R-…-20.S2 from the other side: an ORDINARY seat pool VK whose request arrives
// carrying the internal header is refused, not served by ignoring the header.
// The ingress deletes that header for every other namespace, so its presence
// here means either a rolled-back daemon or a forged inbound value — and the
// cluster port is unauthenticated inside the cluster network, so "ignore it and
// serve normally" would hand the caller a free account picker.
//
// 能红: `if header != "" && route.RouteKind != device_routing_token { ignore }` →
// 200 → red.
//
// spec: R-device-routing-token-dispatch-20.S2（BUT NOT 忽略该头、按席位路径自己选账号）
func TestDeviceRoutingStrict_SeatVKWithHeaderIsRefused(t *testing.T) {
	drtResetStatus(t)
	pinned, _ := drtAccounts(t)
	// A plain seat pool VK: no route kind at all, because it is not a
	// device-routing token.
	pool := newDRTPool(t, "")

	w := pool.serve(t, pinned)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body=%s)", w.Code, w.Body.String())
	}
	drtAssertNoUpstream(t, pool.transport)
	if body := drtDecodeError(t, w); body.Error.Code != observability.ErrCodeDeviceRoutingTokenNodeUnsupported {
		t.Fatalf("error.code = %q, want %q", body.Error.Code, observability.ErrCodeDeviceRoutingTokenNodeUnsupported)
	}

	// Control: the SAME seat VK with no internal header keeps serving exactly as
	// before this task. Without this half the fence could pass by breaking every
	// ordinary pool request.
	if w2 := pool.serve(t, ""); w2.Code != http.StatusOK {
		t.Fatalf("an ordinary seat pool request (no internal header) must be unaffected: status = %d (body=%s)", w2.Code, w2.Body.String())
	}
	if dialed := pool.transport.dialed(); len(dialed) != 1 {
		t.Fatalf("upstream dialed %v, want exactly one call (the header-less control request)", dialed)
	}
}

// ── RED LINE · nothing in the X-Aikey-* namespace reaches an LLM ───────────

// TestDeviceRoutingStrict_NoAikeyHeaderReachesUpstream: the request arrives
// WITH X-Aikey-Route-Account (so the assertion is not vacuous) and the upstream
// must see no header in that namespace at all. Anthropic's OAuth WAF treats an
// unrecognized header as a non-CLI persona signal and answers with an
// evidence-less 429, so a leak here is an availability incident, not cosmetics.
//
// 能红: drop the stripAikeyRequestHeaders call from the forward Director → red.
//
// spec: R-device-routing-token-dispatch-7.S1（上游请求头不含 `X-Aikey-*`）
// 红线: workflow/CI/IDE/claude/principles/no-aikey-headers-to-llm-upstream.md
func TestDeviceRoutingStrict_NoAikeyHeaderReachesUpstream(t *testing.T) {
	drtResetStatus(t)
	pinned, _ := drtAccounts(t)
	pool := newDRTPool(t, routeKindDeviceRoutingToken)

	if w := pool.serve(t, pinned); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	seen := pool.transport.all()
	if len(seen) != 1 {
		t.Fatalf("the upstream was dialed %d times, want 1 — a red-line check that never reached the transport proves nothing", len(seen))
	}
	if got := seen[0].header.Get(headerRouteAccount); got != "" {
		t.Fatalf("red line: %s = %q reached the upstream", headerRouteAccount, got)
	}
	for name := range seen[0].header {
		if strings.HasPrefix(strings.ToLower(name), "x-aikey-") {
			t.Fatalf("red line: upstream-bound header %q is in the X-Aikey-* namespace", name)
		}
	}
	// The inbound request really did carry one, so the strip is what removed it.
	if !strings.EqualFold(headerRouteAccount[:8], "X-Aikey-") {
		t.Fatalf("fixture bug: %q is not in the namespace this fence guards", headerRouteAccount)
	}
}

// TestDeviceRoutingStrict_PickRoutedAccountIsUnchanged pins the OTHER half of
// R-…-11.S1 that a `git diff` cannot: the strict branch consumes the shared pure
// picker, it does not reimplement the pick. If a later change makes the picker
// return anything but the pinned account for a usable override, the strict
// branch must refuse loudly rather than serve someone else.
//
// spec: R-device-routing-token-dispatch-11.S1 静态与快照围栏（`routed_pick.go` 零 diff）
func TestDeviceRoutingStrict_PickRoutedAccountIsUnchanged(t *testing.T) {
	pinned, other := drtAccounts(t)
	refs := []vkeys.GroupAccountRef{{AccountID: drtAccountA}, {AccountID: drtAccountB}}
	material := map[string]vkeys.GroupRuntimeAccount{
		drtAccountA: {CredentialType: "api_key"},
		drtAccountB: {CredentialType: "api_key"},
	}
	got, outcome := vkeys.PickRoutedAccount(drtSeatID, refs, material, pinned, nil, time.Now().Unix())
	if outcome != vkeys.PickOK || got != pinned {
		t.Fatalf("PickRoutedAccount(override=%s) = (%s, %v), want (%s, PickOK) — the strict branch relies on the override winning inside the UNCHANGED picker", pinned, got, outcome, pinned)
	}
	if got == other {
		t.Fatalf("fixture bug: pinned and other are the same account %q", got)
	}
}
