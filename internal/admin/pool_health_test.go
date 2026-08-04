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
	}})
	s := string(b)
	for _, want := range []string{
		`"pool_routing"`, `"enabled":true`, `"account_id":"acc-1"`, `"oauth_group_id":"group-1"`,
		`"seat_id":"seat-1"`, `"cooldown_seconds":42`,
		`"path_health"`, `"path_id":"deadbeef1234"`, `"transport":"mihomo"`,
		`"egress_fingerprint":"f00baa123456"`, `"retry_after_seconds":1`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("status missing %s: %s", want, s)
		}
	}
	for _, secret := range []string{"egress_proxy_url", "base_url", "token", "secret"} {
		if strings.Contains(s, secret) {
			t.Fatalf("status must not expose %q: %s", secret, s)
		}
	}

	// enabled but nothing cooled → cooled_accounts omitted (clean steady state).
	b, _ = json.Marshal(statusResponse{Status: "ok", PoolRouting: &PoolRoutingHealth{Enabled: true}})
	if strings.Contains(string(b), "cooled_accounts") {
		t.Fatalf("empty cooled list must be omitted, got %s", b)
	}
}
