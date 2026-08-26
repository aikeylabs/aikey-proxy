package sysproxy

import "testing"

// TestIsNonPublicDestination pins the classifier that decides whether a failed
// upstream dial gets the "intranet address behind your egress tunnel" hint.
//
// WHY this matters (2026-08-26 staging Cluster): the console's custom-provider
// entry offers 「本地模型 / 中转站 / 企业反代」. Two of those are normally LAN
// addresses, and on a node with `upstream_proxy` they fail at the far end of the
// tunnel with a bare UPSTREAM_ERROR/EOF. Misclassifying here does not break
// routing — it withholds the only clue the operator gets.
// Bugfix: workflow/CI/bugfix/20260826-egress-private-destination-undiagnosable.md
func TestIsNonPublicDestination(t *testing.T) {
	nonPublic := []string{
		// The exact shape that triggered the staging investigation.
		"10.0.0.93",
		// RFC1918, all three blocks.
		"10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.1.50",
		// Loopback (already egress-bypassed, but still intranet-only).
		"127.0.0.1", "localhost", "::1",
		// RFC6598 shared address space — cloud VPC / overlay networks.
		"100.64.0.1", "100.127.255.255",
		// Link-local, incl. the cloud metadata address.
		"169.254.169.254",
		// IPv6 ULA and link-local, bracketed as a URL host would deliver them.
		"fd00::1", "[fd12:3456::9]", "fe80::1",
		// Special-use names that can never resolve publicly.
		"ollama.local", "mock-provider.aikey.internal", "gpu.lan",
		"router.home.arpa", "relay.intranet", "MODELS.INTERNAL",
		// A single-label host has no public parent zone.
		"ollama", "gpu-box",
		// Trailing root dot must not defeat the suffix match.
		"ollama.local.",
	}
	for _, host := range nonPublic {
		if !IsNonPublicDestination(host) {
			t.Errorf("IsNonPublicDestination(%q) = false, want true "+
				"(an intranet target would lose its diagnostic hint)", host)
		}
	}

	public := []string{
		"api.openai.com", "api.anthropic.com", "api.deepseek.com",
		// The staging relay: a PUBLIC address on a non-standard port.
		"120.24.220.105",
		// 172.32 is outside RFC1918; 100.128 is outside RFC6598. Off-by-one guards.
		"172.32.0.1", "172.15.255.255", "100.128.0.1", "100.63.255.255",
		"8.8.8.8", "example.com", "sub.domain.example.co.uk",
	}
	for _, host := range public {
		if IsNonPublicDestination(host) {
			t.Errorf("IsNonPublicDestination(%q) = true, want false "+
				"(a public provider failure would be blamed on the egress tunnel)", host)
		}
	}

	// Empty host must not classify — an unparsable URL is not evidence of intranet.
	if IsNonPublicDestination("") {
		t.Error(`IsNonPublicDestination("") = true, want false`)
	}
}
