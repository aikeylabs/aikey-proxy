package proxy

import (
	"strings"
	"testing"
)

// TestEgressAttribution pins the single-source derivation used by BOTH the live
// egress-attribution log (A) and the usage-event ext_json audit (B). If these
// drift, a request's log and its stored audit would disagree about the egress.
func TestEgressAttribution(t *testing.T) {
	const fragment = "proxies:\n  - name: x\n    type: socks5\n    server: 1.2.3.4\n    port: 443\n    password: SECRET\n"
	cases := []struct {
		name          string
		spec          string
		override      bool
		wantApplied   bool
		wantEngine    string
		wantFPPresent bool
	}{
		{"no egress → direct", "", false, false, "none", false},
		{"fragment applied", fragment, false, true, "mihomo", true},
		{"fragment overridden → not applied", fragment, true, false, "mihomo", true},
		{"socks5 chain", "socks5://a:1,socks5://b:1", false, true, "socks5-chain", true},
		{"single url", "socks5://host:1080", false, true, "single-url", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			applied, engine, fp := egressAttribution(c.spec, c.override)
			if applied != c.wantApplied {
				t.Errorf("applied=%v want %v", applied, c.wantApplied)
			}
			if engine != c.wantEngine {
				t.Errorf("engine=%q want %q", engine, c.wantEngine)
			}
			if (fp != "") != c.wantFPPresent {
				t.Errorf("fingerprint=%q, wantPresent=%v", fp, c.wantFPPresent)
			}
			// Security: the fingerprint must NEVER contain the spec verbatim (a
			// fragment carries socks5 credentials).
			if fp != "" && (len(fp) != 12 || containsSecret(fp)) {
				t.Errorf("fingerprint %q leaked spec content or wrong length", fp)
			}
		})
	}
}

func containsSecret(fp string) bool {
	// The fingerprint is hex(sha256)[:12]; "SECRET"/"socks5"/"proxies" must not appear.
	for _, s := range []string{"SECRET", "socks5", "proxies", "password"} {
		if strings.Contains(fp, s) {
			return true
		}
	}
	return false
}
