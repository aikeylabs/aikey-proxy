package supervisor

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

func TestFilterSignatureChangesWithMaxAction(t *testing.T) {
	full := filterAppSignaturePart("ai-compliance-detector", false, "full")
	warn := filterAppSignaturePart("ai-compliance-detector", false, "warn")
	if full == warn {
		t.Fatal("filter_max_action is absent from the reload signature")
	}
	if got := filterAppSignaturePart("ai-compliance-detector", false, "full"); got != full {
		t.Fatalf("filter signature is not deterministic: %q != %q", got, full)
	}
}

func TestFilterMaxActionReadFailureUsesStableEventName(t *testing.T) {
	if got := observability.EventProxyFilterMaxActionReadFailed; got != "proxy.filter.max_action_read_failed" {
		t.Fatalf("filter max-action read failure event drifted: %q", got)
	}
}
