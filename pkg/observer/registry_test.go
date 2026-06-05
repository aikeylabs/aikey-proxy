// Tests for the observer framework. Each test below targets one of the
// invariants enumerated in plugin-架构设计.md §6 (the P0/P1 list). The
// tests deliberately exercise the failure modes, not just the happy path —
// the value of this framework is "observers misbehaving don't break the
// proxy", so the proof is: misbehave on purpose and check the proxy
// survives.

package observer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// recordingObserver is a StreamingObserver that records the events it
// receives. Default behavior is "well behaved"; the tests use the
// options below to make it misbehave (panic, sleep, retain payload).
type recordingObserver struct {
	mu         sync.Mutex
	startCount int
	endCount   int
	payloads   [][]byte // copies kept by the observer — used by the aliasing test
	latencies  []int

	// behavior knobs
	panicEveryEvent bool          // panic on every OnSSEEvent
	panicOnStart    bool          // panic on OnRequestStart
	sleepOnEvent    time.Duration // sleep this long inside OnSSEEvent
	beforeEvent     func()        // arbitrary hook before each OnSSEEvent
}

func (r *recordingObserver) OnRequestStart(ctx context.Context, req *RequestContext) {
	if r.panicOnStart {
		panic("recordingObserver: OnRequestStart panic (test)")
	}
	r.mu.Lock()
	r.startCount++
	r.mu.Unlock()
}

func (r *recordingObserver) OnSSEEvent(ctx context.Context, req *RequestContext, eventType string, payload []byte) {
	if r.beforeEvent != nil {
		r.beforeEvent()
	}
	if r.sleepOnEvent > 0 {
		time.Sleep(r.sleepOnEvent)
	}
	if r.panicEveryEvent {
		panic("recordingObserver: OnSSEEvent panic (test)")
	}
	// Capture the slice by reference deliberately — the aliasing test
	// inspects whether the registry handed us a private copy by
	// mutating the caller's buffer after the call returns.
	r.mu.Lock()
	r.payloads = append(r.payloads, payload)
	r.mu.Unlock()
}

func (r *recordingObserver) OnRequestEnd(ctx context.Context, req *RequestContext, totalLatencyMs int) {
	r.mu.Lock()
	r.endCount++
	r.latencies = append(r.latencies, totalLatencyMs)
	r.mu.Unlock()
}

func (r *recordingObserver) snapshot() (starts int, ends int, payloads [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pls := make([][]byte, len(r.payloads))
	copy(pls, r.payloads)
	return r.startCount, r.endCount, pls
}

// makeRegistry builds a Registry containing one recordingObserver under a
// test-only slug. Test helpers go through this so the FirstPartyAllowlist
// check never trips during tests.
func makeRegistry(t *testing.T, obs *recordingObserver) *Registry {
	t.Helper()
	// Inject a test slug into the allowlist for the duration of the
	// test. The allowlist is process-global; we restore it on cleanup.
	const testSlug = "_test-recording"
	originalAllow := FirstPartyAllowlist[testSlug]
	FirstPartyAllowlist[testSlug] = true
	t.Cleanup(func() {
		if !originalAllow {
			delete(FirstPartyAllowlist, testSlug)
		}
	})

	resetRegistrationsForTest()
	RegisterObserver(Observer{
		Name:         "test-recording",
		OwnerAppSlug: testSlug,
		// Existing tests use NotifyStart with StreamAppPipeline (mirrors
		// the production rhythm observer's scope). The fixture used to
		// pre-date stream routing, so AllStreams() would also work; the
		// narrower [StreamAppPipeline] is intentional — it exercises the
		// "happy path stream match" rather than the wildcard case.
		Streams:      []string{StreamAppPipeline},
		Build: func(cfg map[string]any) (StreamingObserver, error) {
			return obs, nil
		},
	})

	r := NewRegistry(nil)
	r.BuildObservers(func(string) bool { return true }, nil)
	if got := r.Active(); got != 1 {
		t.Fatalf("expected 1 active observer; got %d", got)
	}
	return r
}

func makeRequest(traceID string) *RequestContext {
	return &RequestContext{
		AppSlug:        "_test-recording",
		AppMode:        "isolated",
		ProtocolFamily: "anthropic",
		TraceID:        traceID,
		StartedAt:      time.Now(),
	}
}

// ---------------------------------------------------------------------------
// P0-1 — payload aliasing
//
// The drainer hands SSE bytes via a reused buffer. The observer runs
// asynchronously on its own goroutine; if we forwarded the buffer
// directly the next Read() would overwrite the observer's "saved" slice.
// The registry must copy at the boundary so the observer can retain
// payload safely.
// ---------------------------------------------------------------------------

func TestNotifySSEEvent_CopiesPayloadAtBoundary(t *testing.T) {
	obs := &recordingObserver{}
	r := makeRegistry(t, obs)

	req := makeRequest("aliasing-1")
	r.NotifyStart(context.Background(), StreamAppPipeline, req)

	// Simulate the drainer's reused buffer: we hand a slice, then
	// mutate the underlying array, then check the observer still has
	// the original bytes.
	buf := []byte("frame-A")
	r.NotifySSEEvent(context.Background(), req, "data", buf)
	// Mutate the caller's buffer in-place after the call returns.
	// In production this is what the drainer's next Read does.
	copy(buf, "MUTATE!")

	// Drain a moment so the consumer goroutine processes the event.
	r.NotifyEnd(context.Background(), req, 10)
	waitForEnd(t, obs, 1)

	_, _, payloads := obs.snapshot()
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload; got %d", len(payloads))
	}
	if got := string(payloads[0]); got != "frame-A" {
		t.Errorf("payload mutated by caller's buffer rewrite — registry did not copy at boundary; got %q", got)
	}
}

// ---------------------------------------------------------------------------
// P0-2 — fan-out backpressure
//
// A slow observer must not be able to block the drainer. The registry
// uses a fixed-size channel + non-blocking send; if the channel is full
// the event is dropped and a counter is incremented. The Notify* call
// must return promptly regardless of observer speed.
// ---------------------------------------------------------------------------

func TestNotifySSEEvent_NonBlockingWhenObserverIsSlow(t *testing.T) {
	obs := &recordingObserver{sleepOnEvent: 100 * time.Millisecond}
	r := makeRegistry(t, obs)

	req := makeRequest("backpressure-1")
	r.NotifyStart(context.Background(), StreamAppPipeline, req)

	// Pump way more than the channel buffer's worth of events as
	// fast as we can; each call MUST return well under the
	// observer's per-event sleep, proving the send is non-blocking.
	const totalEvents = 200
	deadline := 50 * time.Millisecond
	start := time.Now()
	for i := 0; i < totalEvents; i++ {
		r.NotifySSEEvent(context.Background(), req, "data", []byte("x"))
	}
	elapsed := time.Since(start)
	if elapsed > deadline {
		t.Fatalf("NotifySSEEvent blocked: %d calls took %v, expected < %v "+
			"(observer is intentionally slow; the registry must drop on backpressure)", totalEvents, elapsed, deadline)
	}

	// We don't bother draining; the test is "send was fast". Cancel
	// fan-out so the slow consumer exits.
	r.NotifyEnd(context.Background(), req, 0)

	if r.Stats().DroppedEvents == 0 {
		t.Errorf("expected some dropped events under backpressure; got 0 (channel may be too big?)")
	}
}

// ---------------------------------------------------------------------------
// P1-1 — detached ctx
//
// If the client disconnects mid-stream the request ctx is canceled.
// Observer work must NOT be canceled with it — the observer is
// finalizing evidence and reporting independently of the user's
// connection. The registry achieves this by building observer ctx via
// context.WithoutCancel + a separate maxRequestAge timeout.
// ---------------------------------------------------------------------------

func TestObserverCtx_DoesNotInheritParentCancellation(t *testing.T) {
	obs := &recordingObserver{}
	r := makeRegistry(t, obs)

	// Parent ctx we'll cancel mid-stream.
	parent, cancel := context.WithCancel(context.Background())
	req := makeRequest("detached-1")
	r.NotifyStart(parent, StreamAppPipeline, req)
	cancel() // simulate client disconnect

	// Observer work continues regardless: send an event + end.
	r.NotifySSEEvent(parent, req, "data", []byte("after-cancel"))
	r.NotifyEnd(parent, req, 42)

	waitForEnd(t, obs, 1)
	starts, ends, payloads := obs.snapshot()
	if starts != 1 {
		t.Errorf("OnRequestStart not called even though detached ctx should keep observer alive; got starts=%d", starts)
	}
	if ends != 1 {
		t.Errorf("OnRequestEnd not called after parent cancel; detached ctx isn't isolating cancellation")
	}
	if len(payloads) != 1 || string(payloads[0]) != "after-cancel" {
		t.Errorf("OnSSEEvent not delivered after parent cancel; got payloads=%v", payloads)
	}
}

// ---------------------------------------------------------------------------
// P1-2 — panic limiter / auto-disable
//
// A misbehaving observer that panics on every event must not
// (a) take down the proxy, (b) flood crash dumps, or (c) keep being
// called indefinitely. The limiter caps panics per minute; above the
// budget the observer is auto-disabled (subsequent dispatches skip it
// entirely).
// ---------------------------------------------------------------------------

func TestObserver_AutoDisablesAfterPanicBudgetExhausted(t *testing.T) {
	obs := &recordingObserver{panicEveryEvent: true}
	r := makeRegistry(t, obs)

	// Tighten the per-observer panic limiter so we can exhaust the
	// budget in a fast unit test. (Production is 60/min; here we use
	// 5/100ms.)
	for _, ao := range r.observers {
		ao.panicLimiter = newTokenLimiter(5, 100*time.Millisecond)
	}

	req := makeRequest("panic-1")
	r.NotifyStart(context.Background(), StreamAppPipeline, req)

	// Pump enough events to exceed the budget. After auto-disable
	// flips the consumer goroutine sees ao.disabled.Load() == true
	// and stops invoking the observer.
	const events = 50
	for i := 0; i < events; i++ {
		r.NotifySSEEvent(context.Background(), req, "data", []byte("p"))
	}
	r.NotifyEnd(context.Background(), req, 0)

	// Allow consumer goroutine time to drain.
	time.Sleep(50 * time.Millisecond)

	stats := r.Stats()
	if stats.AutoDisabled == 0 {
		t.Fatalf("expected auto-disable to trip; got AutoDisabled=%d, Panics=%d", stats.AutoDisabled, stats.PanicsTotal)
	}
	if r.Active() != 0 {
		t.Errorf("expected 0 active observers after auto-disable; got %d", r.Active())
	}
	// Subsequent requests must not allocate channels for the disabled observer.
	req2 := makeRequest("panic-2")
	r.NotifyStart(context.Background(), StreamAppPipeline, req2)
	rsAny, _ := r.requests.Load(req2.TraceID)
	if rsAny != nil {
		if got := len(rsAny.(*requestState).channels); got != 0 {
			t.Errorf("disabled observer still received a channel for new request; got %d channels", got)
		}
	}
	r.NotifyEnd(context.Background(), req2, 0)
}

// ---------------------------------------------------------------------------
// Allowlist enforcement (R2 first defense line)
// ---------------------------------------------------------------------------

func TestRegisterObserver_RejectsSlugNotInAllowlist(t *testing.T) {
	resetRegistrationsForTest()
	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatal("expected RegisterObserver to panic for unknown slug")
		}
	}()
	RegisterObserver(Observer{
		Name:         "rogue",
		OwnerAppSlug: "bogus-slug-not-in-allowlist",
		Streams:      []string{StreamAppPipeline}, // unused — slug check fails first
		Build:        func(cfg map[string]any) (StreamingObserver, error) { return nil, nil },
	})
}

func TestRegisterObserver_RejectsDuplicateName(t *testing.T) {
	const testSlug = "_test-dup"
	FirstPartyAllowlist[testSlug] = true
	t.Cleanup(func() { delete(FirstPartyAllowlist, testSlug) })
	resetRegistrationsForTest()

	RegisterObserver(Observer{
		Name:         "same-name",
		OwnerAppSlug: testSlug,
		Streams:      []string{StreamAppPipeline},
		Build:        func(cfg map[string]any) (StreamingObserver, error) { return nil, nil },
	})

	defer func() {
		if rec := recover(); rec == nil {
			t.Fatal("expected second RegisterObserver call to panic on duplicate name")
		}
	}()
	RegisterObserver(Observer{
		Name:         "same-name",
		OwnerAppSlug: testSlug,
		Streams:      []string{StreamAppPipeline},
		Build:        func(cfg map[string]any) (StreamingObserver, error) { return nil, nil },
	})
}

// ---------------------------------------------------------------------------
// Build failure path: observer Build errors must NOT block proxy startup.
// ---------------------------------------------------------------------------

func TestBuildObservers_BuildErrorDoesNotPropagate(t *testing.T) {
	const testSlug = "_test-build-err"
	FirstPartyAllowlist[testSlug] = true
	t.Cleanup(func() { delete(FirstPartyAllowlist, testSlug) })
	resetRegistrationsForTest()

	RegisterObserver(Observer{
		Name:         "fails-to-build",
		OwnerAppSlug: testSlug,
		Streams:      []string{StreamAppPipeline},
		Build:        func(cfg map[string]any) (StreamingObserver, error) { return nil, errors.New("nope") },
	})

	r := NewRegistry(nil)
	r.BuildObservers(func(string) bool { return true }, nil)
	if r.Active() != 0 {
		t.Errorf("expected 0 active observers after Build error; got %d", r.Active())
	}
	// Notify* on an empty registry must be a no-op (no panic).
	r.NotifyStart(context.Background(), StreamAppPipeline, makeRequest("empty"))
	r.NotifySSEEvent(context.Background(), makeRequest("empty"), "data", []byte("x"))
	r.NotifyEnd(context.Background(), makeRequest("empty"), 0)
}

// ---------------------------------------------------------------------------
// DefaultVaultEnableCheck
// ---------------------------------------------------------------------------

type fakeVault struct {
	hasRecord    bool
	activeTokens int
	recErr       error
	tokenErr     error
}

type fakeRecord struct{ slug string }

func (f *fakeRecord) GetSlug() string { return f.slug }

func (f *fakeVault) GetAppRecord(slug string) (interface{ GetSlug() string }, error) {
	if f.recErr != nil {
		return nil, f.recErr
	}
	if !f.hasRecord {
		return nil, nil
	}
	return &fakeRecord{slug: slug}, nil
}

func (f *fakeVault) GetActiveAppKeysForSlug(slug string) (int, error) {
	return f.activeTokens, f.tokenErr
}

func TestDefaultVaultEnableCheck(t *testing.T) {
	tests := []struct {
		name string
		v    *fakeVault
		want bool
	}{
		{"app missing", &fakeVault{hasRecord: false}, false},
		{"app present, no active keys", &fakeVault{hasRecord: true, activeTokens: 0}, false},
		{"app present + 1 active key", &fakeVault{hasRecord: true, activeTokens: 1}, true},
		{"app lookup error", &fakeVault{recErr: errors.New("db down")}, false},
		{"token count error", &fakeVault{hasRecord: true, tokenErr: errors.New("db down")}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DefaultVaultEnableCheck("any-slug", tc.v, nil)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// waitForEnd polls obs.endCount until it reaches `want` or the test
// times out. Consumer goroutines run asynchronously so the test must
// wait — but with a hard deadline so a regression doesn't hang the
// suite indefinitely.
func waitForEnd(t *testing.T, obs *recordingObserver, want int) {
	t.Helper()
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		_, ends, _ := obs.snapshot()
		if ends >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	_, ends, _ := obs.snapshot()
	t.Fatalf("OnRequestEnd not reached: want %d, got %d after 1s", want, ends)
}

// Sanity check: the token limiter under load doesn't allow more than
// budget within the window. (Standalone unit; doesn't need the
// registry.)
func TestTokenLimiter_RespectsBudget(t *testing.T) {
	l := newTokenLimiter(3, 100*time.Millisecond)
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.allow() {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("expected 3 allow()=true in burst; got %d", allowed)
	}
}

func TestTokenLimiter_RecoversAfterWindow(t *testing.T) {
	l := newTokenLimiter(2, 30*time.Millisecond)
	for i := 0; i < 5; i++ {
		l.allow()
	}
	time.Sleep(40 * time.Millisecond)
	if !l.allow() {
		t.Errorf("expected limiter to recover after window expired")
	}
}

// ---------------------------------------------------------------------------
// Stream-based dispatch routing (2026-05-23, credential-mode-architecture
// SPEC §1.4.1). Each observer declares Streams; the Registry must skip
// dispatch for observers whose declaration excludes the request's stream.
// ---------------------------------------------------------------------------

// TestRegisterObserver_RejectsEmptyStreams pins the "fail loudly at startup"
// invariant: an observer with empty Streams would silently receive zero
// events at runtime (the SPEC §1.4 routing model relies on declarations).
// Catching it at RegisterObserver(panic) is louder than letting the proxy
// boot with a dead observer.
func TestRegisterObserver_RejectsEmptyStreams(t *testing.T) {
	const testSlug = "_test-empty-streams"
	FirstPartyAllowlist[testSlug] = true
	t.Cleanup(func() { delete(FirstPartyAllowlist, testSlug) })
	resetRegistrationsForTest()

	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatal("expected RegisterObserver to panic on empty Streams")
		}
	}()
	RegisterObserver(Observer{
		Name:         "no-streams",
		OwnerAppSlug: testSlug,
		// Streams intentionally omitted — must panic.
		Build: func(cfg map[string]any) (StreamingObserver, error) { return nil, nil },
	})
}

// TestRegisterObserver_RejectsUnknownStreamName guards against typos in
// observer declarations. A stream name not in AllStreams() means the
// declaration won't ever match a real Notify call site — silent failure.
func TestRegisterObserver_RejectsUnknownStreamName(t *testing.T) {
	const testSlug = "_test-bad-stream"
	FirstPartyAllowlist[testSlug] = true
	t.Cleanup(func() { delete(FirstPartyAllowlist, testSlug) })
	resetRegistrationsForTest()

	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatal("expected RegisterObserver to panic on unknown stream name")
		}
	}()
	RegisterObserver(Observer{
		Name:         "typo-stream",
		OwnerAppSlug: testSlug,
		Streams:      []string{"user-chat"}, // typo: hyphen instead of underscore
		Build:        func(cfg map[string]any) (StreamingObserver, error) { return nil, nil },
	})
}

// TestNotifyStart_SkipsObserverThatDoesNotHandleStream is the core routing
// fence: an observer with Streams=[StreamAppPipeline] must NOT receive
// NotifyStart events from StreamUserChat traffic. Without this filter,
// rhythm-style observers would have to defensively skip non-app events
// inside their own code (the anti-pattern the user identified in P3
// step 2 architecture review).
func TestNotifyStart_SkipsObserverThatDoesNotHandleStream(t *testing.T) {
	const testSlug = "_test-stream-routing"
	FirstPartyAllowlist[testSlug] = true
	t.Cleanup(func() { delete(FirstPartyAllowlist, testSlug) })
	resetRegistrationsForTest()

	obs := &recordingObserver{}
	RegisterObserver(Observer{
		Name:         "only-app-pipeline",
		OwnerAppSlug: testSlug,
		Streams:      []string{StreamAppPipeline},
		Build: func(cfg map[string]any) (StreamingObserver, error) {
			return obs, nil
		},
	})

	r := NewRegistry(nil)
	r.BuildObservers(func(string) bool { return true }, nil)

	req := makeRequest("trace-user-chat-1")
	// Fire under StreamUserChat — observer declared StreamAppPipeline only,
	// so MUST NOT receive any event.
	r.NotifyStart(context.Background(), StreamUserChat, req)
	r.NotifySSEEvent(context.Background(), req, "data", []byte("ignored"))
	r.NotifyEnd(context.Background(), req, 10)

	// Drain time so any (wrongly dispatched) consumer would have run.
	time.Sleep(20 * time.Millisecond)

	starts, ends, payloads := obs.snapshot()
	if starts != 0 {
		t.Errorf("observer with Streams=[app_pipeline] received NotifyStart for user_chat; "+
			"starts = %d, want 0", starts)
	}
	if len(payloads) != 0 {
		t.Errorf("observer with Streams=[app_pipeline] received NotifySSEEvent for user_chat; "+
			"events = %d, want 0", len(payloads))
	}
	if ends != 0 {
		t.Errorf("observer with Streams=[app_pipeline] received NotifyEnd for user_chat; "+
			"ends = %d, want 0", ends)
	}
}

// TestNotifyStart_RoutesToObserverWhenStreamMatches is the positive
// counterpart: fire under StreamAppPipeline → observer with that stream
// declared MUST receive the full Start/SSE/End sequence.
func TestNotifyStart_RoutesToObserverWhenStreamMatches(t *testing.T) {
	const testSlug = "_test-stream-routing-positive"
	FirstPartyAllowlist[testSlug] = true
	t.Cleanup(func() { delete(FirstPartyAllowlist, testSlug) })
	resetRegistrationsForTest()

	obs := &recordingObserver{}
	RegisterObserver(Observer{
		Name:         "only-app-pipeline-pos",
		OwnerAppSlug: testSlug,
		Streams:      []string{StreamAppPipeline},
		Build: func(cfg map[string]any) (StreamingObserver, error) {
			return obs, nil
		},
	})

	r := NewRegistry(nil)
	r.BuildObservers(func(string) bool { return true }, nil)

	req := makeRequest("trace-app-1")
	r.NotifyStart(context.Background(), StreamAppPipeline, req)
	r.NotifySSEEvent(context.Background(), req, "data", []byte("hello"))
	r.NotifyEnd(context.Background(), req, 10)

	// Wait briefly for the async consumer goroutine to drain its channel.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		starts, ends, _ := obs.snapshot()
		if starts >= 1 && ends >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	starts, ends, payloads := obs.snapshot()
	if starts != 1 {
		t.Errorf("observer starts = %d, want 1", starts)
	}
	if len(payloads) != 1 {
		t.Errorf("observer events = %d, want 1", len(payloads))
	}
	if ends != 1 {
		t.Errorf("observer ends = %d, want 1", ends)
	}
}

// ---------------------------------------------------------------------------
// MetadataJSON lazy cache (perf optimisation, 2026-05-23 P3).
// ---------------------------------------------------------------------------

// TestRequestContext_MetadataJSON_ContainsExpectedFields pins the wire
// format (v=1). If observers / NDJSON consumers depend on these field
// names, a tag rename breaks them silently — this test surfaces the
// breakage at compile/test time before it ships.
func TestRequestContext_MetadataJSON_ContainsExpectedFields(t *testing.T) {
	req := &RequestContext{
		TraceID:        "trace-xyz",
		Stream:         "user_chat",
		ProviderID:     "anthropic",
		KeyAlias:       "FreySilvaqzs@qualityservice.com",
		AppSlug:        "compliance-guard",
		AppKeyID:       "uuid-app-1",
		AppMode:        "isolated",
		RequestedModel: "claude-sonnet-4-6",
		ResolvedModel:  "claude-sonnet-4-6-20251001",
		SessionID:      "sess-1",
		ProtocolFamily: "anthropic",
		StartedAt:      time.Unix(1716200000, 0),
	}

	raw, err := req.MetadataJSON()
	if err != nil {
		t.Fatalf("MetadataJSON: %v", err)
	}

	// Field-by-field assertions via parsed map (avoid brittle substring
	// matching that breaks on key-order changes).
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("returned bytes must be valid JSON: %v\nraw: %s", err, raw)
	}
	for k, want := range map[string]any{
		"v":                float64(1),
		"trace_id":         "trace-xyz",
		"stream":           "user_chat",
		"provider":         "anthropic",
		"alias":            "FreySilvaqzs@qualityservice.com",
		"app_slug":         "compliance-guard",
		"app_key_id":       "uuid-app-1",
		"app_mode":         "isolated",
		"requested_model":  "claude-sonnet-4-6",
		"resolved_model":   "claude-sonnet-4-6-20251001",
		"session_id":       "sess-1",
		"protocol_family":  "anthropic",
		"started_at_unix_ms": float64(1716200000 * 1000),
	} {
		if got[k] != want {
			t.Errorf("field %q: got %v (%T), want %v (%T)", k, got[k], got[k], want, want)
		}
	}
}

// TestRequestContext_MetadataJSON_OmitsEmptyFields verifies omitempty is
// honored — wire format stays compact for the user_chat case (no App*
// fields, no AppMode).
func TestRequestContext_MetadataJSON_OmitsEmptyFields(t *testing.T) {
	req := &RequestContext{
		TraceID: "trace-1",
		Stream:  "user_chat",
		// All other string fields intentionally empty.
	}
	raw, err := req.MetadataJSON()
	if err != nil {
		t.Fatalf("MetadataJSON: %v", err)
	}
	s := string(raw)
	for _, k := range []string{"app_slug", "app_key_id", "app_mode", "requested_model",
		"resolved_model", "session_id", "alias", "provider", "protocol_family"} {
		if strings.Contains(s, `"`+k+`"`) {
			t.Errorf("empty field %q must be omitted, got: %s", k, s)
		}
	}
	// v=1 must always be present.
	if !strings.Contains(s, `"v":1`) {
		t.Errorf("v=1 must always be present, got: %s", s)
	}
}

// TestRequestContext_MetadataJSON_ReturnsCachedSliceOnSecondCall pins the
// lazy-cache invariant: the SAME []byte (pointer-identical) comes back
// on subsequent calls. This is the proof that we save the marshal cost
// on N-1 of N observer calls.
//
// We compare via len + capacity + first/last byte rather than
// reflect.SliceHeader (deprecated since Go 1.17). The semantics we care
// about: subsequent calls return the same underlying memory.
func TestRequestContext_MetadataJSON_ReturnsCachedSliceOnSecondCall(t *testing.T) {
	req := &RequestContext{TraceID: "trace-cache", Stream: "user_chat"}

	b1, err := req.MetadataJSON()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	b2, err := req.MetadataJSON()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	// Pointer-identity check via &b1[0] addressing: if cache works, both
	// slices share the same underlying array.
	if &b1[0] != &b2[0] {
		t.Errorf("MetadataJSON did not cache — second call allocated a new buffer "+
			"(b1[0]=%p, b2[0]=%p)", &b1[0], &b2[0])
	}
	if len(b1) != len(b2) {
		t.Errorf("cached length drift: b1=%d, b2=%d", len(b1), len(b2))
	}
}

// TestRequestContext_MetadataJSON_ConcurrentSafe is the contention proof:
// 1000 goroutines call MetadataJSON simultaneously and ALL get the same
// cached slice. sync.Once handles this; this test pins the contract so
// a future refactor that swaps sync.Once for an unguarded check would
// fail under race detector.
//
// Run with: go test -race -run TestRequestContext_MetadataJSON_ConcurrentSafe
func TestRequestContext_MetadataJSON_ConcurrentSafe(t *testing.T) {
	req := &RequestContext{TraceID: "trace-conc", Stream: "user_chat"}

	const goroutines = 1000
	var wg sync.WaitGroup
	wg.Add(goroutines)
	results := make([][]byte, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			b, err := req.MetadataJSON()
			if err != nil {
				t.Errorf("goroutine %d: error: %v", idx, err)
				return
			}
			results[idx] = b
		}(i)
	}
	wg.Wait()

	// All results must point at the same backing array (the cached slice).
	first := results[0]
	if first == nil {
		t.Fatal("first result nil — race?")
	}
	for i := 1; i < goroutines; i++ {
		if results[i] == nil {
			t.Errorf("goroutine %d returned nil", i)
			continue
		}
		if &results[i][0] != &first[0] {
			t.Errorf("goroutine %d got a different underlying array — cache broken "+
				"(want %p, got %p)", i, &first[0], &results[i][0])
			return
		}
	}
}

// TestAllStreams_StableAndComplete pins the stream-vocabulary contract:
// adding/removing a stream is a coordinated SPEC + framework + caller
// change. If you intentionally update AllStreams, update SPEC §1.4.1 +
// rhythm/ndjson-fanout declarations + proxy.go call sites in one PR.
func TestAllStreams_StableAndComplete(t *testing.T) {
	want := []string{"user_chat", "app_pipeline", "probe"}
	got := AllStreams()
	if len(got) != len(want) {
		t.Fatalf("AllStreams: len=%d, want %d", len(got), len(want))
	}
	for i, s := range want {
		if got[i] != s {
			t.Errorf("AllStreams[%d] = %q, want %q (SPEC §1.4.1 ordering drift)", i, got[i], s)
		}
	}
}

// Compile-time assertion: recordingObserver is a StreamingObserver.
var _ StreamingObserver = (*recordingObserver)(nil)

// Compile-time assertion: registry counters are 64-bit aligned for
// 32-bit atomic safety. atomic.Int64 handles alignment automatically;
// this check just documents the intent.
var _ = atomic.Int64{}
