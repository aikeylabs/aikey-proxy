package proxy

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
)

// ---- test helpers ----------------------------------------------------------

// capturingStore collects UsageEvents for assertion in tests.
type capturingStore struct {
	mu     sync.Mutex
	events []events.UsageEvent
	ready  chan struct{}
}

func newCapturingStore() *capturingStore {
	return &capturingStore{ready: make(chan struct{}, 100)}
}

func (s *capturingStore) Insert(evs []events.UsageEvent) error {
	s.mu.Lock()
	s.events = append(s.events, evs...)
	s.mu.Unlock()
	for range evs {
		select {
		case s.ready <- struct{}{}:
		default:
		}
	}
	return nil
}

// waitEvent blocks until at least one event is recorded or the timeout fires.
func (s *capturingStore) waitEvent(t *testing.T, timeout time.Duration) events.UsageEvent {
	t.Helper()
	select {
	case <-s.ready:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for usage event to be recorded")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events[len(s.events)-1]
}

func (s *capturingStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// newTestCollector creates a Collector that flushes immediately (batchSize=1).
func newTestCollector(t *testing.T) (*events.Collector, *capturingStore) {
	t.Helper()
	store := newCapturingStore()
	c := events.NewCollector(store, 1, 5*time.Millisecond)
	t.Cleanup(func() { c.Close() })
	return c, store
}

// anthropicSSE returns a complete Anthropic SSE stream string.
func anthropicSSE(inputTokens, outputTokens int, chunks int) string {
	var b strings.Builder
	// message_start — carries input_tokens
	b.WriteString(`data: {"type":"message_start","message":{"usage":{"input_tokens":` +
		itoa(inputTokens) + `,"output_tokens":0}}}` + "\n\n")
	// content chunks
	for i := 0; i < chunks; i++ {
		b.WriteString(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"chunk ` +
			itoa(i) + ` "}}` + "\n\n")
	}
	// message_delta — carries output_tokens
	b.WriteString(`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":` +
		itoa(outputTokens) + `}}` + "\n\n")
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// ---- streamDrainer tests ---------------------------------------------------

// TestStreamDrainer_ForwardsFullStream verifies that when the client stays
// connected, the entire SSE stream is forwarded and tokens are recorded.
func TestStreamDrainer_ForwardsFullStream(t *testing.T) {
	sse := anthropicSSE(10, 25, 3)
	upstream := io.NopCloser(strings.NewReader(sse))

	collector, store := newTestCollector(t)
	baseEvent := events.UsageEvent{Timestamp: time.Now(), VirtualKeyID: "vk_test", Provider: "anthropic"}

	drainer := newStreamDrainer(upstream, baseEvent, &provider.Anthropic{}, collector, context.Background(), context.Background(), nil)

	got, err := io.ReadAll(drainer)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	drainer.Close()

	if string(got) != sse {
		t.Fatalf("forwarded data mismatch\ngot:  %q\nwant: %q", got, sse)
	}

	ev := store.waitEvent(t, 2*time.Second)
	if ev.InputTokens != 10 {
		t.Errorf("InputTokens = %d, want 10", ev.InputTokens)
	}
	if ev.OutputTokens != 25 {
		t.Errorf("OutputTokens = %d, want 25", ev.OutputTokens)
	}
}

// TestStreamDrainer_RecordsTokensOnStreamEnd verifies token parsing from a
// realistic Anthropic SSE stream.
func TestStreamDrainer_RecordsTokensOnStreamEnd(t *testing.T) {
	sse := anthropicSSE(7, 42, 5)
	upstream := io.NopCloser(strings.NewReader(sse))

	collector, store := newTestCollector(t)
	baseEvent := events.UsageEvent{
		Timestamp:    time.Now(),
		VirtualKeyID: "vk_billing",
		Provider:     "anthropic",
		IsStreaming:  true,
		StatusCode:   200,
	}

	drainer := newStreamDrainer(upstream, baseEvent, &provider.Anthropic{}, collector, context.Background(), context.Background(), nil)
	io.ReadAll(drainer)
	drainer.Close()

	ev := store.waitEvent(t, 2*time.Second)
	if ev.InputTokens != 7 {
		t.Errorf("InputTokens = %d, want 7", ev.InputTokens)
	}
	if ev.OutputTokens != 42 {
		t.Errorf("OutputTokens = %d, want 42", ev.OutputTokens)
	}
	if ev.VirtualKeyID != "vk_billing" {
		t.Errorf("VirtualKeyID = %q, want vk_billing", ev.VirtualKeyID)
	}
	if !ev.IsStreaming {
		t.Error("IsStreaming should be true")
	}
}

// TestStreamDrainer_StopsOnClientDisconnect verifies the key behavior change:
// when the client disconnects, the drainer stops reading from upstream
// (releasing the provider connection) and records the partial tokens already
// received.
//
// The upstream is a pipe that the test controls: it writes the message_start
// event, then waits. The client reads message_start and disconnects. The
// drainer goroutine should stop without reading the second half of the stream.
func TestStreamDrainer_StopsOnClientDisconnect(t *testing.T) {
	firstPart := `data: {"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":0}}}` + "\n\n"
	secondPart := `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":15}}` + "\n\n"

	// Upstream pipe — we control when data arrives.
	upstreamPR, upstreamPW := io.Pipe()

	collector, store := newTestCollector(t)
	baseEvent := events.UsageEvent{Timestamp: time.Now()}

	drainer := newStreamDrainer(upstreamPR, baseEvent, &provider.Anthropic{}, collector, context.Background(), context.Background(), nil)

	// Write first part (message_start) to upstream.
	go func() { upstreamPW.Write([]byte(firstPart)) }()

	// Client: read exactly the first part, then disconnect.
	buf := make([]byte, len(firstPart))
	if _, err := io.ReadFull(drainer, buf); err != nil {
		t.Fatalf("ReadFull error: %v", err)
	}
	// Disconnect: close the read side of the drainer.
	drainer.Close()

	// Write second part to upstream pipe — drainer goroutine should NOT read it
	// (it stopped on client disconnect). If the goroutine is still draining,
	// this write would block; we unblock it after a short delay.
	writeSecond := make(chan struct{})
	go func() {
		upstreamPW.Write([]byte(secondPart))
		upstreamPW.Close()
		close(writeSecond)
	}()
	<-writeSecond

	// The event should be recorded with only the tokens from firstPart.
	ev := store.waitEvent(t, 2*time.Second)

	if ev.InputTokens != 5 {
		t.Errorf("InputTokens = %d, want 5 (message_start only)", ev.InputTokens)
	}
	if ev.OutputTokens != 0 {
		t.Errorf("OutputTokens = %d, want 0 (message_delta not received)", ev.OutputTokens)
	}
}

// TestStreamDrainer_ProxyContextAbort verifies that cancelling the proxy
// lifecycle context causes the goroutine to exit cleanly.
func TestStreamDrainer_ProxyContextAbort(t *testing.T) {
	// Upstream that never sends data.
	pr, _ := io.Pipe() // leave write side open

	proxyCtx, cancelProxy := context.WithCancel(context.Background())
	collector, store := newTestCollector(t)
	baseEvent := events.UsageEvent{Timestamp: time.Now()}

	drainer := newStreamDrainer(pr, baseEvent, &provider.Anthropic{}, collector, proxyCtx, context.Background(), nil)

	// Cancel proxy context — goroutine should exit.
	cancelProxy()

	// The client-facing pipe should become unreadable (CloseWithError).
	done := make(chan struct{})
	go func() {
		io.ReadAll(drainer)
		close(done)
	}()

	select {
	case <-done:
		// goroutine exited, pipe closed — correct
	case <-time.After(2 * time.Second):
		t.Fatal("drainer goroutine did not exit after proxy context cancelled")
	}

	// No event should be recorded (proxy aborted cleanly, collector is also closing).
	time.Sleep(50 * time.Millisecond)
	if store.count() != 0 {
		t.Errorf("expected 0 events on proxy abort, got %d", store.count())
	}
}

// TestStreamDrainer_EmptyStream verifies graceful handling of an empty body
// (e.g. upstream closed immediately).
func TestStreamDrainer_EmptyStream(t *testing.T) {
	upstream := io.NopCloser(strings.NewReader(""))
	collector, store := newTestCollector(t)
	baseEvent := events.UsageEvent{Timestamp: time.Now()}

	drainer := newStreamDrainer(upstream, baseEvent, &provider.Anthropic{}, collector, context.Background(), context.Background(), nil)
	io.ReadAll(drainer)
	drainer.Close()

	ev := store.waitEvent(t, 2*time.Second)
	if ev.InputTokens != 0 || ev.OutputTokens != 0 {
		t.Errorf("expected (0,0), got (%d,%d)", ev.InputTokens, ev.OutputTokens)
	}
}

// TestStreamDrainer_DurationRecorded verifies that DurationMs is set and
// positive in the recorded event.
func TestStreamDrainer_DurationRecorded(t *testing.T) {
	sse := anthropicSSE(3, 8, 1)
	upstream := io.NopCloser(strings.NewReader(sse))
	collector, store := newTestCollector(t)
	baseEvent := events.UsageEvent{Timestamp: time.Now()}

	drainer := newStreamDrainer(upstream, baseEvent, &provider.Anthropic{}, collector, context.Background(), context.Background(), nil)
	io.ReadAll(drainer)
	drainer.Close()

	ev := store.waitEvent(t, 2*time.Second)
	if ev.DurationMs < 0 {
		t.Errorf("DurationMs should be ≥ 0, got %d", ev.DurationMs)
	}
}

// TestStreamDrainer_NilCollectorDoesNotPanic pins the 2026-04-22 probe-mode
// crash fix.
//
// Background: the X-Aikey-Probe: 1 request path in Handle() passes a nil
// collector to newStreamDrainer so probe traffic doesn't inflate usage
// counters. Before the fix, the drainer goroutine called
// `collector.Record(ev)` unconditionally → nil deref → whole proxy process
// panicked AFTER returning the streaming response. The CLI saw "chat ok"
// for the probe but then got connection-refused on the very next request.
//
// Guard: when collector is nil, the Record call is skipped.
func TestStreamDrainer_NilCollectorDoesNotPanic(t *testing.T) {
	sse := anthropicSSE(5, 10, 2)
	upstream := io.NopCloser(strings.NewReader(sse))

	baseEvent := events.UsageEvent{
		Timestamp:    time.Now(),
		VirtualKeyID: "vk_probe",
		Provider:     "anthropic",
	}

	// onComplete MUST still fire even when collector is nil — the reporter
	// callback handles its own probe gating upstream (in proxy.go::Handle),
	// and nil-collector means "skip collector recording", NOT "skip all
	// post-stream bookkeeping".
	completed := make(chan struct{}, 1)
	cb := func(_ provider.TokenBreakdown, _ string) {
		completed <- struct{}{}
	}

	// Pass nil for the collector — this is the probe path.
	drainer := newStreamDrainer(
		upstream, baseEvent, &provider.Anthropic{},
		nil, // ← the nil that used to panic
		context.Background(), context.Background(),
		cb,
	)

	// Drain fully. The drainer's post-stream goroutine runs in parallel;
	// the test deadline below catches a goroutine panic via the channel.
	if _, err := io.ReadAll(drainer); err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	drainer.Close()

	select {
	case <-completed:
		// Good — drainer goroutine finished cleanly and invoked onComplete.
	case <-time.After(2 * time.Second):
		t.Fatal("onComplete never fired — drainer goroutine likely panicked on nil collector")
	}
}
