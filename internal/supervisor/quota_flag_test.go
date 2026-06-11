package supervisor

import "testing"

// Fence for the 2026-06-11 default flip (user-approved): quota enforcement is
// ON by default; PROXY_QUOTA_ENABLED is an explicit OPT-OUT kill switch. The
// previous default-OFF caused enterprise hard_block quotas to be silently
// unenforced when a deployment role forgot the env (bug
// 20260611-cluster-worker-quota-not-enabled). If a refactor reverts the
// default, these assertions catch it before another silent-bypass ships.
func TestQuotaEnabledDefaultOn(t *testing.T) {
	t.Setenv("PROXY_QUOTA_ENABLED", "")
	if !quotaEnabledFromEnv() {
		t.Fatal("quota must default ON when PROXY_QUOTA_ENABLED is unset/empty")
	}
}

func TestQuotaEnabledExplicitOptOut(t *testing.T) {
	for _, v := range []string{"0", "false", "no", "off", "OFF", " False "} {
		t.Setenv("PROXY_QUOTA_ENABLED", v)
		if quotaEnabledFromEnv() {
			t.Fatalf("PROXY_QUOTA_ENABLED=%q must disable quota (kill switch)", v)
		}
	}
}

func TestQuotaEnabledLegacyOnValuesStillOn(t *testing.T) {
	// Pre-flip deployments (cluster-node.env, DE units, e2e compose) set "1";
	// they must keep working unchanged as redundant belt-and-braces.
	for _, v := range []string{"1", "true", "yes", "on"} {
		t.Setenv("PROXY_QUOTA_ENABLED", v)
		if !quotaEnabledFromEnv() {
			t.Fatalf("PROXY_QUOTA_ENABLED=%q must keep quota enabled", v)
		}
	}
}
