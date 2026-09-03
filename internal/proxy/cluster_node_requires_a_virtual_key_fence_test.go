package proxy

// cluster_node_requires_a_virtual_key_fence_test.go — the fence under the
// cluster node's inbound authentication.
//
// # What went wrong
//
// Proxy.Handle dispatches the provider path-prefix branch (/anthropic/v1/...)
// at step 0 and RETURNS; virtual-key extraction is step 1. A request on that URL
// shape therefore never reached the token check, and one carrying no aikey token
// resolved from the default binding instead — correct on a developer's loopback
// proxy, an unauthenticated relay on a cluster node whose vault holds the
// organisation's keys and whose listen address is routable.
//
// Measured 2026-09-02 from the public internet against a real node, with no
// credential: 200, served by a member's virtual key, recorded in usage_fact_dwd
// against that member's SEAT.
//
// config.validate() had already reasoned about this. It refuses a non-loopback
// bind unless cluster.enabled, and says a cluster node "is protected by VK-token
// auth" instead. That premise was false on this branch. The rail was real; the
// protection it was traded for did not exist.
//
// # Why the fence has to be two-sided
//
// The cheapest way to make the refusal half pass is to stop serving the
// path-prefix branch in cluster mode at all — which would break every
// legitimate cluster client, because that is the URL shape they use. So the
// serving half is asserted with equal weight: a request carrying a real aikey
// token must NOT get this refusal.
//
// See workflow/CI/bugfix/2026-09-02-集群节点代理是一个公网开放中继.md

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// clusterNodeProbe issues one path-prefix request against a proxy in the given
// mode and returns the status and the error code the client would switch on.
//
// 🔴 licensePlane is left nil on purpose: ForwardingAllowed() is true for a nil
// cache, so the license gate cannot mask the authentication decision under test.
// A denied gate answers 402 before ever reaching this branch — which is exactly
// what made the defect survivable in the field, and must not make it survivable
// here.
func clusterNodeProbe(t *testing.T, cluster bool, header, value string) (int, string) {
	t.Helper()
	p := &Proxy{clusterNode: cluster}
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages",
		strings.NewReader(`{"model":"claude-3-5-haiku-20241022","messages":[]}`))
	if header != "" {
		req.Header.Set(header, value)
	}
	rec := httptest.NewRecorder()
	p.Handle(rec, req)

	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body.Error.Code
}

// TestAClusterNodeRefusesAPathPrefixRequestThatNamesNoKey is the half the defect
// was.
//
// 🔴 The second case is not a variation on the first. The request that actually
// succeeded from the internet carried `x-api-key: ak-not-a-real-key` — a
// syntactically fine, entirely made-up credential. ClassifyToken calls that
// Tier3Native, the same class as "no header at all", and a fence that only
// covered the empty case would leave the exploited one open.
func TestAClusterNodeRefusesAPathPrefixRequestThatNamesNoKey(t *testing.T) {
	for _, tc := range []struct{ name, header, value string }{
		{"no credential at all", "", ""},
		{"a made-up x-api-key (the shape that was exploited)", "x-api-key", "ak-not-a-real-key"},
		{"a made-up bearer", "Authorization", "Bearer sk-zzzz-completely-different"},
		{"the follow-active sentinel, which names no key", "x-api-key", "aikey_active_anthropic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, errCode := clusterNodeProbe(t, true, tc.header, tc.value)
			if code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d.\nA cluster node served a path-prefix request "+
					"that named no virtual key. On a node the vault holds the ORGANISATION's "+
					"keys and the listen address is routable, so this is an open relay over "+
					"the customer's credentials — and the usage lands on a real member's seat.",
					code, http.StatusUnauthorized)
			}
			if errCode != "TOKEN_MISSING" {
				t.Errorf("error code = %q, want TOKEN_MISSING — the same code Handle's step 1 "+
					"gives a token-less request on every other URL shape. From the caller's "+
					"side it is the same mistake and must read the same way.", errCode)
			}
		})
	}
}

// TestAClusterNodeStillServesARequestThatNamesAKey is the half that keeps the
// fix honest.
//
// 🚫 It does NOT assert success — this harness has no registry, so a real token
// legitimately fails further down with TOKEN_INVALID ("not found in registry").
// What it asserts is that the request got PAST the authentication gate, i.e.
// that the fix narrowed the branch rather than switching it off. Without this,
// `if p.clusterNode { return 401 }` — which breaks every cluster client — would
// pass the fence above.
func TestAClusterNodeStillServesARequestThatNamesAKey(t *testing.T) {
	for _, tc := range []struct{ name, header, value string }{
		{"team virtual key", "Authorization", "Bearer aikey_team_some-vk-id"},
		{"personal virtual key", "x-api-key", "aikey_personal_" + strings.Repeat("a", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errCode := clusterNodeProbe(t, true, tc.header, tc.value)
			if errCode == "TOKEN_MISSING" {
				t.Fatalf("a request carrying a virtual key was refused with TOKEN_MISSING. "+
					"The cluster guard is refusing the branch instead of refusing anonymity, "+
					"which breaks every legitimate cluster client — they all use this exact "+
					"URL shape. (%s: %s)", tc.header, tc.value)
			}
		})
	}
}

// TestANonClusterProxyIsUnchanged pins the Personal / Trial / Production
// contract.
//
// 🔴 "No token → the default binding" is not a bug there, it is the product:
// Claude CLI and Cursor send their own credential to a proxy bound to loopback
// and it is substituted. Whoever tightens this next must not tighten it here —
// and would otherwise find out from a user, not from CI.
func TestANonClusterProxyIsUnchanged(t *testing.T) {
	code, errCode := clusterNodeProbe(t, false, "", "")
	if code == http.StatusUnauthorized && errCode == "TOKEN_MISSING" {
		t.Fatalf("a NON-cluster proxy refused a token-less path-prefix request. That is the "+
			"Personal contract — a loopback proxy substituting the credential for a client "+
			"that sends its own — and the cluster guard must not reach it. (got %d/%s)",
			code, errCode)
	}
}
