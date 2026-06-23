package events

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

// TestCollectorRecord_BufferFull_DropsLoudly is the fence test for P1-1: when the
// collector's buffer is full, the dropped event must NOT vanish silently. It must
// (1) increment an externally-readable counter (Metrics().Dropped) and (2) emit a
// structured WARN carrying event.name / error.code + trace correlation, per the
// project's fail-loud + logging-conventions rules.
//
// White-box (package events): we construct a Collector with a deliberately full
// channel and DO NOT start its run loop, so Record() deterministically takes the
// overflow branch — no timing/flooding required.
func TestCollectorRecord_BufferFull_DropsLoudly(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// cap-1 channel pre-filled => any further Record hits the default branch.
	c := &Collector{ch: make(chan UsageEvent, 1)}
	c.ch <- UsageEvent{} // occupy the only slot

	c.Record(&UsageEvent{
		TraceID: "trace-abc", SpanID: "span-1", RequestID: "req-9",
		VirtualKeyID: "vk_test", Provider: "anthropic", Model: "claude-x",
		SessionID: "sess-7",
	})

	// (1) counter incremented and externally readable.
	if got := c.Metrics().Dropped; got != 1 {
		t.Fatalf("Metrics().Dropped = %d, want 1", got)
	}

	// (2) a compliant WARN was emitted with the required fields + values.
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("expected one JSON WARN line, got %q (err %v)", buf.String(), err)
	}
	wantFields := map[string]string{
		"level":          "WARN",
		"event.name":     "usage.collector.buffer_full_drop",
		"error.code":     "USAGE_COLLECTOR_BUFFER_FULL",
		"trace_id":       "trace-abc",
		"span_id":        "span-1",
		"request_id":     "req-9",
		"virtual_key_id": "vk_test",
		"provider":       "anthropic",
		"session_id":     "sess-7",
	}
	for k, want := range wantFields {
		if got, _ := rec[k].(string); got != want {
			t.Errorf("WARN field %q = %q, want %q", k, got, want)
		}
	}
	if dt, ok := rec["dropped_total"].(float64); !ok || dt != 1 {
		t.Errorf("WARN dropped_total = %v, want 1", rec["dropped_total"])
	}
}

// TestCollectorRecord_HappyPath_NoDropNoWarn confirms the normal enqueue path
// neither drops nor warns — guards against the drop branch firing spuriously.
func TestCollectorRecord_HappyPath_NoDropNoWarn(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	c := &Collector{ch: make(chan UsageEvent, 4)}
	c.Record(&UsageEvent{VirtualKeyID: "vk_ok"})

	if got := c.Metrics().Dropped; got != 0 {
		t.Errorf("Metrics().Dropped = %d, want 0", got)
	}
	if len(c.ch) != 1 {
		t.Errorf("channel len = %d, want 1 (event enqueued)", len(c.ch))
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected WARN on happy path: %q", buf.String())
	}
}
