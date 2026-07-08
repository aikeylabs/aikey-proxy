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
		Enabled:        true,
		CooledAccounts: []CooledAccount{{AccountID: "acc-1", CooldownSeconds: 42}},
	}})
	s := string(b)
	for _, want := range []string{`"pool_routing"`, `"enabled":true`, `"account_id":"acc-1"`, `"cooldown_seconds":42`} {
		if !strings.Contains(s, want) {
			t.Fatalf("status missing %s: %s", want, s)
		}
	}

	// enabled but nothing cooled → cooled_accounts omitted (clean steady state).
	b, _ = json.Marshal(statusResponse{Status: "ok", PoolRouting: &PoolRoutingHealth{Enabled: true}})
	if strings.Contains(string(b), "cooled_accounts") {
		t.Fatalf("empty cooled list must be omitted, got %s", b)
	}
}
