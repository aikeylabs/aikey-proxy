package cluster

// Fence for hop ① of the node capability gate (需求包 codex-pool-anti-linkage,
// task 4.8).
//
// spec: R-device-routing-token-dispatch-20 节点能力闸 —— 节点随注册 / 心跳上报本
// 程序支持的能力；控制面解析时核对，缺能力则 503、不转发也不改选节点。
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/device-routing-token-dispatch/spec.md
//
// This hop is fenced against a FIXED fake hub on purpose: it must stay red or
// green on its own, without waiting for the hub parser (hop ②) or the control
// plane (hop ③). The cross-process chain is fenced separately (task 4.13).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// capabilityCapturingHub records the last register/heartbeat body it received.
func capabilityCapturingHub(t *testing.T, last *atomic.Value) *httptest.Server {
	t.Helper()
	record := func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		last.Store(m)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"registered":true,"heartbeat_interval_seconds":5}`))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/register", record)
	mux.HandleFunc("/cluster/heartbeat", record)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestNodeHealthPayload_AdvertisesDeviceRoutingCapability(t *testing.T) {
	var last atomic.Value
	srv := capabilityCapturingHub(t, &last)

	r := NewRegistrar(srv.URL, "n1", "10.0.0.1:27200", 1, "")
	r.SetHealthSource(func() map[string]any {
		return map[string]any{"proxy": map[string]any{"version": "vX"}}
	})

	// Both hops of the node→hub wire carry it: a node that only ever registers
	// (long heartbeat interval) must be judged capable too.
	if err := r.register(context.Background()); err != nil {
		t.Fatalf("register: %v", err)
	}
	assertAdvertisedCapability(t, "register", last.Load(), 0, 0)

	if err := r.heartbeat(context.Background()); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	assertAdvertisedCapability(t, "heartbeat", last.Load(), 0, 0)

	// The counters are supplied by an injected provider — this task reports 0/0
	// (no self-check exists yet); task 4.5 installs the real one and only the
	// numbers change.
	r.SetDeviceRoutingTokenStatsSource(func() DeviceRoutingTokenStats {
		return DeviceRoutingTokenStats{RouteKindMissingActive: 2, RouteKindMissingTotal: 7}
	})
	if err := r.heartbeat(context.Background()); err != nil {
		t.Fatalf("heartbeat with stats: %v", err)
	}
	assertAdvertisedCapability(t, "heartbeat with stats source", last.Load(), 2, 7)

	// Mixed fleet: a registrar with no health source keeps the legacy bare wire
	// shape. Advertising must not be smuggled into a payload that used to carry
	// no `health` at all (see TestHeartbeatCarriesHealth — that assertion stands).
	bare := NewRegistrar(srv.URL, "n2", "10.0.0.2:27200", 1, "")
	if err := bare.heartbeat(context.Background()); err != nil {
		t.Fatalf("bare heartbeat: %v", err)
	}
	body, _ := last.Load().(map[string]any)
	if _, present := body["health"]; present {
		t.Fatalf("a registrar without a health source must stay on the bare wire shape: %#v", body)
	}
}

// assertAdvertisedCapability pins the JSON path the hub parses:
// health.capabilities[] ∋ "device_routing_token" and
// health.device_routing_token.{route_kind_missing_active,route_kind_missing_total}.
func assertAdvertisedCapability(t *testing.T, what string, body any, wantActive, wantTotal float64) {
	t.Helper()
	m, ok := body.(map[string]any)
	if !ok {
		t.Fatalf("%s: no body captured", what)
	}
	health, ok := m["health"].(map[string]any)
	if !ok {
		t.Fatalf("%s: health section missing: %#v", what, m)
	}
	caps, ok := health["capabilities"].([]any)
	if !ok {
		t.Fatalf("%s: health.capabilities missing: %#v", what, health)
	}
	found := false
	for _, c := range caps {
		if c == CapabilityDeviceRoutingToken {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s: capabilities %v must advertise %q", what, caps, CapabilityDeviceRoutingToken)
	}
	drt, ok := health["device_routing_token"].(map[string]any)
	if !ok {
		t.Fatalf("%s: health.device_routing_token missing: %#v", what, health)
	}
	if drt["route_kind_missing_active"] != wantActive || drt["route_kind_missing_total"] != wantTotal {
		t.Fatalf("%s: counters = %v, want active=%v total=%v", what, drt, wantActive, wantTotal)
	}
}
