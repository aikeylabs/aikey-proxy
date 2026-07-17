package config

import (
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/egress"
)

// Fence for the 2026-07-17 node-upstream validation fix: /user/settings must
// accept the SAME forms the runtime supports — a single http/socks5 URL AND a
// socks5 chain — and reject a multi-protocol fragment early (this OSS test binary
// links only the built-in socks5 engine, so MultiProtocolAvailable() is false)
// with an actionable "enterprise offline package" message rather than the old
// cryptic "invalid control character in URL".
func TestValidateUpstreamProxyURL_AcceptsChainRejectsFragmentOnOSS(t *testing.T) {
	if egress.MultiProtocolAvailable() {
		t.Skip("this fence asserts OSS (mihomo-free) behavior; multi-protocol engine is linked")
	}
	ok := []string{
		"",                                     // clear → direct
		"http://127.0.0.1:7890",                // single http
		"socks5://user:pass@exit-host:1080",    // single socks5
		"socks5://front:1080,socks5://exit:1080", // socks5 CHAIN — the bug: used to be rejected
	}
	for _, s := range ok {
		if err := ValidateUpstreamProxyURL(s); err != nil {
			t.Errorf("ValidateUpstreamProxyURL(%q) = %v, want nil", s, err)
		}
	}

	// A multi-protocol fragment must be rejected with a clear, actionable message
	// on the GPL-free build — not accepted (then failing at dial) and not a
	// net/url control-character error.
	frag := "proxies:\n  - name: x\n    type: ss\n    server: h\n    port: 8002\n    cipher: rc4-md5"
	err := ValidateUpstreamProxyURL(frag)
	if err == nil {
		t.Fatal("fragment accepted on a build without the multi-protocol engine — must be rejected")
	}
	if !strings.Contains(err.Error(), "enterprise offline package") {
		t.Errorf("fragment rejection message = %q, want it to mention the enterprise offline package (actionable)", err.Error())
	}
	if strings.Contains(err.Error(), "invalid control character") {
		t.Errorf("still the old cryptic url.Parse error: %q", err.Error())
	}

	// A malformed single URL still fails (scheme guard).
	if err := ValidateUpstreamProxyURL("ftp://host:21"); err == nil {
		t.Error("ftp:// scheme must be rejected")
	}
}
