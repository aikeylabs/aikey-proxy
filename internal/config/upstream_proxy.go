// upstream_proxy.go — runtime read/modify/write of the egress (upstream) proxy URL.
//
// WHY this lives here (2026-06-30, R25 出口收敛 follow-up): the OAuth/AI egress
// proxy used to be a master-side system_settings value; the egress-convergence
// refactor moved that responsibility to the PROXY NODE (cfg.UpstreamProxy.URL).
// The local web "Settings → Upstream proxy" card lets a user set it without hand-
// editing yaml; the admin endpoint persists it HERE and hot-swaps the live
// transport + impersonate client (no restart). Decision record: user picked
// hot-swap (B) + plaintext storage (i).
//
// Storage = aikey-user.yaml's `proxy.upstream_proxy.url` (the USER layer). The
// proxy's Load() already deep-merges the user file's `proxy:` subtree onto the
// system config's top level (see config.go loadAndMaybeMerge + configmerge), so a
// value written here survives `make restart-personal` re-renders of the system
// yaml. We never touch the system aikey-proxy.yaml (it's template-rendered).
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/AiKeyLabs/pkg/egress"
	"gopkg.in/yaml.v3"
)

// ValidateUpstreamProxyURL accepts "" (clear → direct egress), a single http/
// https/socks5 URL with host:port, a socks5 CHAIN (socks5://front,socks5://exit),
// or a multi-protocol config FRAGMENT (proxies/proxy-groups). Chains and fragments
// are delegated to egress.ValidateSpec so /user/settings accepts exactly the same
// forms as the master per-account editor (config alignment).
//
// Bugfix 2026-07-17: chains + fragments were rejected here even though the node
// upstream RUNTIME (BuildEgressTransport → egress.BuildDialer) already supports
// them — egress.ValidateSpec was written to be shared by this caller (see its
// docstring) but was never wired. Fragments additionally need the multi-protocol
// (mihomo) engine, which only the enterprise offline package links; on the
// GPL-free OSS build we reject a fragment early with an actionable message rather
// than accepting it and failing at dial time ("server set a fragment, local can't
// dial it").
func ValidateUpstreamProxyURL(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil // empty = clear the proxy (direct egress)
	}
	// Engine spec (socks5 chain or config fragment) → the egress engine handles it.
	if strings.Contains(s, ",") || egress.IsFragment(s) {
		if egress.IsFragment(s) && !egress.MultiProtocolAvailable() {
			return fmt.Errorf("multi-protocol egress (ss/vmess/trojan/… or a fallback group) needs the enterprise offline package; " +
				"this build supports a single http/socks5 URL or a socks5 chain (e.g. socks5://front:1080,socks5://exit:1080)")
		}
		return egress.ValidateSpec(s)
	}
	// Single URL (http/https/socks5).
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	default:
		return fmt.Errorf("scheme must be http/https/socks5, got %q", u.Scheme)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return fmt.Errorf("host:port required (e.g. http://127.0.0.1:7890)")
	}
	return nil
}

// userConfigPathFor returns the aikey-user.yaml path next to the system config.
func userConfigPathFor(systemConfigPath string) string {
	return filepath.Join(filepath.Dir(systemConfigPath), "aikey-user.yaml")
}

// PersistUpstreamProxyURL writes url into aikey-user.yaml's `proxy.upstream_proxy.url`
// via read-modify-write, preserving every other field the CLI owns there
// (collector_routes, collector_credentials, …). An empty url is written as an
// explicit "" so the user layer overrides any system-template default with "direct
// egress" (deep-merge keeps the empty string as a value, not an absence).
//
// systemConfigPath is the path the proxy was loaded from (--config); the user file
// is resolved next to it. The write is atomic (temp + rename) with 0600 perms.
func PersistUpstreamProxyURL(systemConfigPath, rawURL string) error {
	userPath := userConfigPathFor(systemConfigPath)

	// Load existing user file (absent ⇒ start empty; the personal-no-team case).
	root := map[string]any{}
	if b, err := os.ReadFile(userPath); err == nil {
		if err := yaml.Unmarshal(b, &root); err != nil {
			return fmt.Errorf("parse %s: %w", userPath, err)
		}
		if root == nil {
			root = map[string]any{}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", userPath, err)
	}

	// Navigate/create proxy.upstream_proxy and set url, preserving siblings.
	proxySec := asStringMap(root["proxy"])
	upstream := asStringMap(proxySec["upstream_proxy"])
	upstream["url"] = rawURL
	proxySec["upstream_proxy"] = upstream
	root["proxy"] = proxySec

	out, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("marshal user config: %w", err)
	}
	return atomicWrite(userPath, out)
}

// asStringMap coerces a yaml-decoded value into a map[string]any we can extend.
// yaml.v3 decodes mappings into map[string]any already; a nil / wrong-typed value
// (e.g. the key was absent or held a scalar) is replaced with a fresh map so the
// caller can always set into it.
func asStringMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return map[string]any{}
}

// atomicWrite writes data to a temp file in the target dir then renames it over
// path, so a crash mid-write can't leave a truncated config. 0600 because the URL
// may carry credentials (socks5://user:pass@host) — same posture as the rest of
// aikey-user.yaml.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".aikey-user-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp config into place: %w", err)
	}
	return nil
}
