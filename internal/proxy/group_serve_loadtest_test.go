package proxy

import "testing"

func TestLoadtestUpstreamAllowed(t *testing.T) {
	t.Setenv("AIKEY_LOADTEST_ALLOWED_UPSTREAM_HOSTS", "replay-provider,fixtures.test")
	for _, target := range []string{
		"http://127.0.0.1:39090",
		"http://[::1]:39090",
		"http://localhost:39090",
		"http://replay-provider:39090",
		"https://child.fixtures.test/v1/messages",
	} {
		if !loadtestUpstreamAllowed(target) {
			t.Fatalf("expected load-test upstream to be allowed: %s", target)
		}
	}
	for _, target := range []string{
		"https://api.anthropic.com",
		"https://notfixtures.test",
		"file:///tmp/provider",
		"not-a-url",
	} {
		if loadtestUpstreamAllowed(target) {
			t.Fatalf("expected load-test upstream to be blocked: %s", target)
		}
	}
}
