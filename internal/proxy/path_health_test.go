package proxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func testPathRoute(baseURL, egress string) *vkeys.ResolvedRoute {
	return &vkeys.ResolvedRoute{
		ProviderCode: "anthropic", ProtocolType: "anthropic",
		BaseURL: baseURL, EgressProxyURL: "socks5://" + egress,
	}
}

func containsProviderPathValue(path ProviderPath, needle string) bool {
	return strings.Contains(path.Key, needle) ||
		strings.Contains(path.OriginFingerprint, needle) ||
		strings.Contains(path.EgressFingerprint, needle)
}

func TestProviderPathHealth_StateMachineRecoversWithoutFixedAccountCooldown(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m := NewProviderPathHealthManager()
	m.now = func() time.Time { return now }
	path := ProviderPath{
		Key: "path-a", Provider: "anthropic", Protocol: "anthropic",
		Transport: "node",
	}

	if permit := m.Permit(path); !permit.Allowed || permit.Probe {
		t.Fatalf("closed path must allow a normal request, got %+v", permit)
	}
	first := m.NoteTransportFailure(path, pathFailureTransport)
	if first.State != pathStateSuspect || first.ConsecutiveFailures != 1 {
		t.Fatalf("first transport failure must be suspect, got %+v", first)
	}

	probe := m.Permit(path)
	if !probe.Allowed || !probe.Probe || probe.Health.State != pathStateHalfOpen {
		t.Fatalf("next distinct request must become the single half-open probe, got %+v", probe)
	}
	if concurrent := m.Permit(path); concurrent.Allowed || concurrent.RetryAfter < time.Second {
		t.Fatalf("concurrent half-open request must be rejected with retry guidance, got %+v", concurrent)
	}

	opened := m.NoteTransportFailure(path, pathFailureTransport)
	if opened.State != pathStateOpen || opened.ConsecutiveFailures != 2 || opened.RetryAfterSeconds != 1 {
		t.Fatalf("second consecutive transport failure must open for 1s, got %+v", opened)
	}
	if blocked := m.Permit(path); blocked.Allowed || blocked.RetryAfter < time.Second {
		t.Fatalf("open path must reject before retry_at, got %+v", blocked)
	}

	now = now.Add(time.Second)
	probe = m.Permit(path)
	if !probe.Allowed || !probe.Probe {
		t.Fatalf("elapsed backoff must admit one half-open probe, got %+v", probe)
	}
	m.NoteHTTPResponse(path)
	if got := m.Snapshot(); len(got) != 0 {
		t.Fatalf("any HTTP response proves path reachability and must close it, got %+v", got)
	}
}

func TestProviderPathHealth_BackoffCapsAtTenSeconds(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m := NewProviderPathHealthManager()
	m.now = func() time.Time { return now }
	path := ProviderPath{Key: "path-a", Provider: "openai", Protocol: "openai_compatible", Transport: "node"}

	m.NoteTransportFailure(path, pathFailureTransport)
	for i, want := range []int{1, 2, 4, 8, 10, 10} {
		permit := m.Permit(path)
		if !permit.Allowed || !permit.Probe {
			t.Fatalf("failure %d: probe not admitted: %+v", i+2, permit)
		}
		h := m.NoteTransportFailure(path, pathFailureTransport)
		if h.RetryAfterSeconds != want {
			t.Fatalf("failure %d: retry=%ds want %ds", i+2, h.RetryAfterSeconds, want)
		}
		now = now.Add(time.Duration(want) * time.Second)
	}
}

func TestProviderPathHealth_InputChangeAndCanceledProbeRecoverImmediately(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m := NewProviderPathHealthManager()
	m.now = func() time.Time { return now }
	path := ProviderPath{Key: "path-a", Provider: "anthropic", Protocol: "anthropic", Transport: "mihomo", EgressFingerprint: "abc123"}

	m.NoteTransportFailure(path, pathFailureEgressDial)
	_ = m.Permit(path)
	m.NoteTransportFailure(path, pathFailureEgressDial) // open
	if permit := m.Permit(path); permit.Allowed {
		t.Fatalf("path must be blocked before a network change, got %+v", permit)
	}

	m.NotifyInputsChanged()
	probe := m.Permit(path)
	if !probe.Allowed || !probe.Probe {
		t.Fatalf("network/transport/override change must admit an immediate half-open probe, got %+v", probe)
	}
	m.NoteProbeCanceled(path)
	if retry := m.Permit(path); !retry.Allowed || !retry.Probe {
		t.Fatalf("client cancellation must release the half-open slot without counting a failure, got %+v", retry)
	}
}

func TestProviderPathForRoute_NeverContainsRawEgressOrOrigin(t *testing.T) {
	route := testPathRoute("https://api.example.test/private", "user:secret@10.0.0.1:1080")
	path := providerPathForRoute(route, false)
	if path.Key == "" || path.OriginFingerprint == "" || path.EgressFingerprint == "" {
		t.Fatalf("path must carry non-secret stable identities, got %+v", path)
	}
	for _, secret := range []string{"api.example.test", "user", "secret", "10.0.0.1"} {
		if containsProviderPathValue(path, secret) {
			t.Fatalf("provider path surface leaked %q: %+v", secret, path)
		}
	}
}

func TestProviderPathDecision_InFlightRequestKeepsAdmittedOverride(t *testing.T) {
	route := testPathRoute("https://api.example.test/v1", "127.0.0.1:1080")
	pinned := providerPathDecision{path: providerPathForRoute(route, false), overrideOn: false}
	ctx := context.WithValue(context.Background(), ctxKeyProviderPathDecision, pinned)

	got := providerPathDecisionForRequest(ctx, route, true)
	if got.path.Key != pinned.path.Key || got.overrideOn {
		t.Fatalf("concurrent override update changed an in-flight path decision: got=%+v want=%+v", got, pinned)
	}
}
