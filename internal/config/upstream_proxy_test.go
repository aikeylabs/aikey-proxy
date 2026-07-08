package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidateUpstreamProxyURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"empty clears", "", false},
		{"http ok", "http://127.0.0.1:7890", false},
		{"https ok", "https://proxy.example.com:8443", false},
		{"socks5 ok", "socks5://127.0.0.1:7891", false},
		{"socks5 with creds ok", "socks5://user:pass@127.0.0.1:7891", false},
		{"bad scheme", "ftp://127.0.0.1:21", true},
		{"missing port", "http://127.0.0.1", true},
		{"missing host", "http://:7890", true},
		{"garbage", "://nonsense", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateUpstreamProxyURL(c.url)
			if c.wantErr && err == nil {
				t.Fatalf("ValidateUpstreamProxyURL(%q) = nil, want error", c.url)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("ValidateUpstreamProxyURL(%q) = %v, want nil", c.url, err)
			}
		})
	}
}

// TestPersistUpstreamProxyURL_RoundTripThroughLoad: persisting the URL must land in
// aikey-user.yaml AND be read back by the real Load() merge as cfg.UpstreamProxy.URL.
// End-to-end so a future change to either the writer or the merge can't silently
// break "Settings → Upstream proxy".
func TestPersistUpstreamProxyURL_RoundTripThroughLoad(t *testing.T) {
	sysPath := writeTestPair(t, systemProxyYaml, "") // no user file yet
	if err := PersistUpstreamProxyURL(sysPath, "http://127.0.0.1:7890"); err != nil {
		t.Fatalf("PersistUpstreamProxyURL: %v", err)
	}
	cfg, err := Load(sysPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.UpstreamProxy.URL != "http://127.0.0.1:7890" {
		t.Fatalf("UpstreamProxy.URL = %q, want http://127.0.0.1:7890", cfg.UpstreamProxy.URL)
	}
	// The user file must now exist (created when absent).
	if _, err := os.Stat(filepath.Join(filepath.Dir(sysPath), "aikey-user.yaml")); err != nil {
		t.Fatalf("aikey-user.yaml should have been created: %v", err)
	}
}

// TestPersistUpstreamProxyURL_PreservesSiblings: the read-modify-write must keep the
// CLI-owned proxy.* fields (e.g. an events.collector_routes override written by
// `aikey login --control-url`) intact — we only touch upstream_proxy.url. Re-read the
// user file directly (not via Load) to assert exactly what was persisted.
func TestPersistUpstreamProxyURL_PreservesSiblings(t *testing.T) {
	userYaml := `
proxy:
  events:
    collector_routes:
      team: "http://team.example.com:3000"
`
	sysPath := writeTestPair(t, systemProxyYaml, userYaml)
	if err := PersistUpstreamProxyURL(sysPath, "socks5://127.0.0.1:7891"); err != nil {
		t.Fatalf("PersistUpstreamProxyURL: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(filepath.Dir(sysPath), "aikey-user.yaml"))
	if err != nil {
		t.Fatalf("read user file: %v", err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(b, &root); err != nil {
		t.Fatalf("parse user file: %v", err)
	}
	proxy, _ := root["proxy"].(map[string]any)
	up, _ := proxy["upstream_proxy"].(map[string]any)
	if up["url"] != "socks5://127.0.0.1:7891" {
		t.Fatalf("upstream_proxy.url not persisted: %v", up["url"])
	}
	events, _ := proxy["events"].(map[string]any)
	cr, _ := events["collector_routes"].(map[string]any)
	if cr["team"] != "http://team.example.com:3000" {
		t.Fatalf("events.collector_routes.team sibling clobbered: %v", cr["team"])
	}
}

// TestPersistUpstreamProxyURL_EmptyClears: writing "" overrides any system default
// with direct egress (empty string is a value the merge keeps, not an absence).
func TestPersistUpstreamProxyURL_EmptyClears(t *testing.T) {
	// System yaml that ships a default upstream_proxy, to prove the user "" wins.
	sysWithProxy := systemProxyYaml + "\nupstream_proxy:\n  url: \"http://10.0.0.1:1080\"\n"
	sysPath := writeTestPair(t, sysWithProxy, "")
	if err := PersistUpstreamProxyURL(sysPath, ""); err != nil {
		t.Fatalf("PersistUpstreamProxyURL: %v", err)
	}
	cfg, err := Load(sysPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.UpstreamProxy.URL != "" {
		t.Fatalf("empty persist should clear egress, got %q", cfg.UpstreamProxy.URL)
	}
}
