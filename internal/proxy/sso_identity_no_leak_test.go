package proxy

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 🔴 FENCE I13 — no member identity reaches the LLM upstream.
//
// The 2026-07-20 first-login change gave every SSO member three new identifying
// values: the Feishu union_id, the tenant_key, and a synthetic account handle
// (sso+<provider>.<digest>@sso.local). All three live in the control plane. None
// has any business on the wire to Anthropic or OpenAI:
//
//   - Anthropic's OAuth WAF reads unrecognized headers as "this is not a real
//     Claude Code session" and answers 429 with no X-RateLimit-Reset — a business
//     rejection that looks like rate limiting and is diagnosed as such for days.
//   - and quite apart from the WAF, shipping a customer's employee identifiers to
//     a third-party model provider is a data-collection surface nobody authorized.
//
// The stripper works by namespace, so it covers annotations that do not exist
// yet — which is the point. A denylist of today's header names would not.
func TestUpstreamRequest_CarriesNoMemberIdentity(t *testing.T) {
	h := http.Header{}
	// Every identity-shaped annotation an internal caller might plausibly stash.
	h.Set("X-Aikey-Union-Id", "on_stub_union_0001")
	h.Set("X-Aikey-Tenant-Key", "stub_tenant_key")
	h.Set("X-Aikey-Account-Email", "sso+feishu.f11625f5ed9c39bf2c63d742cf65e3cc@sso.local")
	h.Set("x-aikey-account-id", "c4f1aec0-326d-4f20-a20a-90fcc100af00")
	h.Set("X-Aikey-Feishu-Token", "u-stub-user-access-token")
	h.Set("X-Aikey-Seat-Id", "3e527d39-d5a8-46ee-a7ac-7ca2072e65b6")
	// Headers the upstream legitimately needs — these must survive.
	h.Set("Authorization", "Bearer real-upstream-token")
	h.Set("Content-Type", "application/json")
	h.Set("anthropic-version", "2023-06-01")

	stripAikeyRequestHeaders(h)

	for name, values := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-aikey-") {
			t.Errorf("identity header %q survived and would reach the model provider", name)
		}
		for _, v := range values {
			for _, forbidden := range []string{"on_stub_union", "stub_tenant_key", "@sso.local", "sso+feishu"} {
				if strings.Contains(v, forbidden) {
					t.Errorf("header %q carries %q to the upstream", name, forbidden)
				}
			}
		}
	}
	if h.Get("Authorization") != "Bearer real-upstream-token" ||
		h.Get("Content-Type") != "application/json" || h.Get("anthropic-version") != "2023-06-01" {
		t.Errorf("the scrub took a header the upstream needs: %#v", h)
	}
}

// The second half of the same invariant, and the one a header test cannot give:
// the proxy must not KNOW these values at all. A stripper only removes what
// someone put on; this asserts nobody in the forwarding path has the vocabulary
// to put them on in the first place.
//
// 🚫 If this fails, do not add a header to the stripper — ask why the data plane
// is holding a member's provider identity.
func TestProxySource_DoesNotReferenceMemberIdentityFields(t *testing.T) {
	forbidden := []string{"union_id", "tenant_key", "sso.local"}
	var offenders []string

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, term := range forbidden {
			if strings.Contains(string(body), term) {
				offenders = append(offenders, path+" contains "+term)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk proxy sources: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("the data plane references control-plane member identity:\n  %s", strings.Join(offenders, "\n  "))
	}
}
