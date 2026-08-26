package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// probeKey is the second surface the 2026-08-25 custom-provider defect reached.
//
// It resolved the wire protocol through the STRICT table lookup before it ever
// looked at t.BaseURL, so a fully specified third-party target — custom vendor
// code, declared protocol, explicit relay address — was refused with
// `no unique provider route`. The connectivity check therefore reported a
// configuration error for a relay it could have reached, while the console
// still listed the credential as a channel.
//
// Docs: workflow/CI/bugfix/20260825-custom-thirdparty-provider-axes-rejected.md
func TestProbeKey_CustomThirdPartyProviderIsProbeable(t *testing.T) {
	var gotPath, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	status, err := probeKey(context.Background(), upstream.Client(), &KeyCheckTarget{
		Provider: "thirdparty_relay", // absent from provider_fingerprint.yaml on purpose
		Protocol: "openai_compatible",
		BaseURL:  upstream.URL + "/v1",
		APIKey:   "sk-relay-test",
	})
	if err != nil {
		t.Fatalf("probeKey on a custom third-party provider: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status=%d, want 200", status)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("outbound path=%q, want /v1/chat/completions", gotPath)
	}
	if gotAuth != "Bearer sk-relay-test" {
		t.Errorf("Authorization=%q, want Bearer sk-relay-test", gotAuth)
	}
}

// The widening admits a DECLARED protocol, not an arbitrary one, and it must not
// invent an address for a provider that has no row to take one from.
func TestProbeKey_CustomProviderRejectsInventedProtocolAndMissingAddress(t *testing.T) {
	t.Run("invented protocol", func(t *testing.T) {
		_, err := probeKey(context.Background(), http.DefaultClient, &KeyCheckTarget{
			Provider: "thirdparty_relay",
			Protocol: "not_a_protocol",
			BaseURL:  "http://unused.invalid/v1",
			APIKey:   "k",
		})
		if err == nil || !strings.Contains(err.Error(), "no unique provider route") {
			t.Fatalf("err=%v, want a no-unique-provider-route rejection", err)
		}
	})

	t.Run("no base url", func(t *testing.T) {
		_, err := probeKey(context.Background(), http.DefaultClient, &KeyCheckTarget{
			Provider: "thirdparty_relay",
			Protocol: "openai_compatible",
			BaseURL:  "",
			APIKey:   "k",
		})
		if err == nil || !strings.Contains(err.Error(), "no base URL") {
			t.Fatalf("err=%v, want a missing-base-URL rejection", err)
		}
	})
}
