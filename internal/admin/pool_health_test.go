package admin

import (
	"encoding/json"
	"strings"
	"testing"
)

// N9 health surface contract: pool_routing is omitted from /status unless set
// (so non-pool deployments are byte-unchanged), and serializes the cooled-account
// shape the operator monitoring the first pool batch reads.
func TestStatusResponse_PoolRoutingSerialization(t *testing.T) {
	// nil → omitted entirely.
	b, _ := json.Marshal(statusResponse{Status: "ok"})
	if strings.Contains(string(b), "pool_routing") {
		t.Fatalf("nil PoolRouting must be omitted from /status, got %s", b)
	}

	// set → present with the cooled-account roster.
	b, _ = json.Marshal(statusResponse{Status: "ok", PoolRouting: &PoolRoutingHealth{
		Enabled: true,
		CooledAccounts: []CooledAccount{{
			AccountID: "acc-1", OAuthGroupID: "group-1", SeatID: "seat-1",
			CooldownSeconds: 42,
		}},
		PathHealth: []ProviderPathHealth{{
			PathID: "deadbeef1234", Provider: "anthropic", Protocol: "anthropic",
			Transport: "mihomo", EgressFingerprint: "f00baa123456", State: "open",
			FailureClass: "egress_dial", ConsecutiveFailures: 2, RetryAfterSeconds: 1,
		}},
		SignalReporting: &SignalReportingHealth{
			Status: "degraded", ConsecutiveFailures: 3, LastAttemptAt: 100,
			LastSuccessAt: 50, LastError: "signal report rejected with HTTP 503",
			PendingSignals: 7, DroppedSignals: 2,
		},
	}})
	s := string(b)
	for _, want := range []string{
		`"pool_routing"`, `"enabled":true`, `"account_id":"acc-1"`, `"oauth_group_id":"group-1"`,
		`"seat_id":"seat-1"`, `"cooldown_seconds":42`,
		`"path_health"`, `"path_id":"deadbeef1234"`, `"transport":"mihomo"`,
		`"egress_fingerprint":"f00baa123456"`, `"retry_after_seconds":1`,
		`"signal_reporting"`, `"status":"degraded"`, `"consecutive_failures":3`,
		`"pending_signals":7`, `"dropped_signals":2`,
		// Device-routing counters (task 4.5). Reported even at zero — a
		// degradation signal that vanishes when it is zero is indistinguishable
		// from a build that cannot report it, and a release check asserting
		// "zero" would then pass on an absent field.
		// spec: R-device-routing-token-dispatch-7.S3 / -20.S2
		`"device_routing_token"`, `"decision_missing_24h":0`,
		`"route_kind_missing_active":0`, `"route_kind_missing_total":0`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("status missing %s: %s", want, s)
		}
	}
	// The leak scan's keywords are deliberately broad. `device_routing_token` is
	// a FEATURE name (the counter object above), not a credential, so it is
	// allow-listed BY NAME and only in object position: normalizing it away before
	// the scan keeps the bare "token" keyword at FULL strength everywhere else,
	// and the shape check below means re-purposing this key to carry a string
	// value still trips the guard.
	if !strings.Contains(s, `"device_routing_token":{`) {
		t.Fatalf("device_routing_token must serialize as an object of counters, never a scalar: %s", s)
	}
	scan := strings.ReplaceAll(s, `"device_routing_token":{`, `"<counters>":{`)
	for _, secret := range []string{"egress_proxy_url", "base_url", "token", "secret"} {
		if strings.Contains(scan, secret) {
			t.Fatalf("status must not expose %q: %s", secret, s)
		}
	}

	// enabled but nothing cooled → cooled_accounts omitted (clean steady state).
	b, _ = json.Marshal(statusResponse{Status: "ok", PoolRouting: &PoolRoutingHealth{Enabled: true}})
	if strings.Contains(string(b), "cooled_accounts") {
		t.Fatalf("empty cooled list must be omitted, got %s", b)
	}
}
