package app

import (
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/egress"
)

// TestProbeTargetsDelegateToSharedDefault fences the SHAPE of the fix, not just
// its current value: both node-side probes must READ egress.DefaultEchoURL rather
// than restate a literal.
//
// Why a separate fence when the neutrality fences below already exist: those pass
// for any neutral literal, so a copy re-pasted here stays green until it drifts —
// which is exactly how the control plane sat on a different default for three
// weeks (2026-08-14). This one goes red the moment a copy reappears.
func TestProbeTargetsDelegateToSharedDefault(t *testing.T) {
	for _, tc := range []struct{ name, env string }{
		{"default", ""},
		{"air-gapped override", "http://echo.internal.example/ip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(egress.EchoURLEnv, tc.env)
			want := egress.DefaultEchoURL()
			if got := upstreamProbeTarget(); got != want {
				t.Errorf("upstreamProbeTarget() = %q, want egress.DefaultEchoURL() = %q — "+
					"do not restate the target here, delegate to the shared definition", got, want)
			}
			if got := egressSelfCheckEcho(); got != want {
				t.Errorf("egressSelfCheckEcho() = %q, want egress.DefaultEchoURL() = %q — "+
					"do not restate the target here, delegate to the shared definition", got, want)
			}
		})
	}
}

// providerHostFragments are the provider hostnames a LEAVING probe must never
// default to. Kept as fragments (not exact URLs) so a variant like
// "https://api.anthropic.com/v1/models" is caught too.
var providerHostFragments = []string{
	"anthropic.com",
	"claude.ai",
	"openai.com",
	"chatgpt.com",
	"googleapis.com",
	"moonshot.cn",
	"bigmodel.cn",
}

// TestUpstreamProbeTargetIsNeutral fences the "Test connectivity" probe target.
//
// This probe leaves the machine through a JUST-PASTED egress node, user-triggered,
// so it is the single worst place to touch a provider: the exit's first packet to
// Anthropic would be an unauthenticated GET. egressSelfCheckEcho already carries
// this rule ("NEVER default to claude.ai", §5.4 #2); this target silently didn't
// until 2026-07-24.
//
// It is also a correctness fence, not only a policy one: Cloudflare-fronted
// providers blackhole datacenter IP ranges with no RST, so a provider target made
// a WORKING tunnel report "context deadline exceeded" and blocked saving it.
func TestUpstreamProbeTargetIsNeutral(t *testing.T) {
	t.Setenv("AIKEY_EGRESS_TEST_ECHO", "")
	got := strings.ToLower(upstreamProbeTarget())
	if got == "" {
		t.Fatal("upstreamProbeTarget() is empty — the probe would have no target")
	}
	for _, frag := range providerHostFragments {
		if strings.Contains(got, frag) {
			t.Errorf("upstreamProbeTarget() = %q, which targets provider host %q.\n"+
				"This probe dials OUT through a user-supplied egress; it must stay a neutral echo.\n"+
				"See the function's comment and egressSelfCheckEcho (§5.4 #2).", got, frag)
		}
	}
}

// TestUpstreamProbeTargetHonorsEnv proves the air-gapped override works and that it
// shares ONE knob with the other two probes, so a private deployment points all of
// them at an internal echo with a single variable.
func TestUpstreamProbeTargetHonorsEnv(t *testing.T) {
	const internal = "http://echo.internal.example/ip"
	t.Setenv("AIKEY_EGRESS_TEST_ECHO", internal)
	if got := upstreamProbeTarget(); got != internal {
		t.Errorf("upstreamProbeTarget() = %q, want the AIKEY_EGRESS_TEST_ECHO override %q", got, internal)
	}
	// Same variable must drive the self-check echo — that shared behavior is the
	// documented contract ("one behavior across control-plane and node").
	if got := egressSelfCheckEcho(); got != internal {
		t.Errorf("egressSelfCheckEcho() = %q, want %q — the two probes must share one knob", got, internal)
	}
}

// TestProxyResolutionTargetStaysProviderShaped is the deliberate INVERSE of the
// fence above, and exists so nobody "fixes" it to match.
//
// proxyResolutionTarget never leaves the process: egressState builds a Request from
// it purely to ask http.Transport which proxy it would select. The answer is
// proxy-rule dependent, so it must look like real provider traffic — a NO_PROXY
// listing the echo host but not the provider would otherwise make `aikey env`
// report an egress that contradicts the hot path.
func TestProxyResolutionTargetStaysProviderShaped(t *testing.T) {
	if !strings.Contains(proxyResolutionTarget, "anthropic.com") {
		t.Errorf("proxyResolutionTarget = %q; it must stay a provider URL.\n"+
			"It is resolution-only (never dialed) and must be representative of\n"+
			"provider traffic for NO_PROXY matching. Do not swap it for the neutral echo.",
			proxyResolutionTarget)
	}
	if proxyResolutionTarget == upstreamProbeTarget() {
		t.Error("proxyResolutionTarget and upstreamProbeTarget() must not converge — " +
			"one is representative-and-never-dialed, the other leaves the machine and must be neutral")
	}
}
