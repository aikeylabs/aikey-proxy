package proxy

// E1 fence (方案 20260819-入口错误可见性与调度日志覆盖 W1): a group-lane DIAL
// failure must reach the unified scheduling log, not just local slog. Before
// the hook, only the PRE-dial breaker refusal (respondProviderPathUnavailable →
// degradeGroup) reported a scheduling event — the first failing request of
// every path-health window died inside ReverseProxy.ErrorHandler with zero
// central trace, which is exactly the blind spot the staging P0-1 outage sat
// in (three entrances 503, master log empty).
//
// Chain fence, not a field fence: it drives a REAL request through Handle →
// group lane → failing transport → ErrorHandler, and asserts on the reporter's
// event channel (hand-copied-relay lesson: fence the chain).

import (
	"errors"
	"net/http"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func TestGroupServe_DialFailureEmitsSchedulingEvent(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-dial", ProviderCode: "anthropic", CredentialID: "cred-dial"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-dial": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-dial",
		}, "oauth-tok-dial"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-dial", OauthGroupID: "grp-dial",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	tr.errByAuth = map[string]error{
		"Bearer oauth-tok-dial": errors.New("dial tcp 10.0.0.93:9090: connection refused"),
	}
	p.signalReporter = looplessSignalReporter()

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("dial failure: status=%d body=%s (want 503)", w.Code, w.Body.String())
	}

	var got []schedulingEventSample
drain:
	for {
		select {
		case ev := <-p.signalReporter.evIn:
			got = append(got, ev)
		default:
			break drain
		}
	}
	var found *schedulingEventSample
	for i := range got {
		if got[i].EventName == observability.EventProxyGroupProviderPathState {
			found = &got[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no %s scheduling event emitted on dial failure (events=%+v) — "+
			"the dial-failure leg is invisible to the master scheduling log",
			observability.EventProxyGroupProviderPathState, got)
	}
	if found.ErrorCode != observability.ErrCodeGroupUpstreamUnavailable {
		t.Fatalf("event error_code=%q want %q (must share the single code exit with the pre-dial refusal)",
			found.ErrorCode, observability.ErrCodeGroupUpstreamUnavailable)
	}
	if found.OauthGroupID != "grp-dial" || found.SeatID != "seat-dial" || found.AccountID != "acc-dial" {
		t.Fatalf("event subject mismatch: group=%q seat=%q account=%q", found.OauthGroupID, found.SeatID, found.AccountID)
	}
	if found.CredentialID != "cred-dial" {
		t.Fatalf("event credential=%q want cred-dial (master ownership gate keys on it)", found.CredentialID)
	}
}
