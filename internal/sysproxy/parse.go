// parse.go — pure parsers for the two platform proxy-setting wire formats.
// Kept build-tag-free so fixture tests run on every development platform
// (test-fixture rule: each wire format gets fixture-based coverage).
package sysproxy

import (
	"net"
	"strings"
)

// parseScutilProxy parses `scutil --proxy` output (macOS). Relevant keys:
//
//	HTTPEnable : 1        HTTPProxy : 127.0.0.1     HTTPPort : 7890
//	HTTPSEnable : 1       HTTPSProxy : 127.0.0.1    HTTPSPort : 7890
//	SOCKSEnable : 1       SOCKSProxy : 127.0.0.1    SOCKSPort : 7891
//
// An entry contributes only when its *Enable flag is 1 AND a host is present.
// PAC (ProxyAutoConfigEnable) is NOT supported — evaluating a PAC script needs
// a JS engine; a PAC-only setup yields an empty snapshot (direct), same as the
// pre-detection behavior, so nothing regresses.
func parseScutilProxy(out string) Snapshot {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	entry := func(prefix, scheme string) string {
		if kv[prefix+"Enable"] != "1" {
			return ""
		}
		host, port := kv[prefix+"Proxy"], kv[prefix+"Port"]
		if host == "" || port == "" {
			return ""
		}
		return scheme + "://" + net.JoinHostPort(host, port)
	}
	return Snapshot{
		HTTP:  entry("HTTP", "http"),
		HTTPS: entry("HTTPS", "http"), // HTTPS entry = proxy for https targets; the proxy itself speaks plain HTTP CONNECT
		SOCKS: entry("SOCKS", "socks5"),
	}
}

// parseWindowsProxyServer parses the registry `ProxyServer` value (used only
// when `ProxyEnable` is 1). Two wire formats exist:
//
//	"host:port"                                     → one proxy for all protocols
//	"http=h:p;https=h:p;ftp=h:p;socks=h:p"          → per-protocol entries
//
// A leading scheme ("http://host:port") is tolerated and stripped.
func parseWindowsProxyServer(val string) Snapshot {
	val = strings.TrimSpace(val)
	if val == "" {
		return Snapshot{}
	}
	if !strings.Contains(val, "=") {
		u := "http://" + stripScheme(val)
		return Snapshot{HTTP: u, HTTPS: u}
	}
	var s Snapshot
	for _, part := range strings.Split(val, ";") {
		proto, hp, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || hp == "" {
			continue
		}
		hp = stripScheme(hp)
		switch strings.ToLower(strings.TrimSpace(proto)) {
		case "http":
			s.HTTP = "http://" + hp
		case "https":
			s.HTTPS = "http://" + hp
		case "socks":
			s.SOCKS = "socks5://" + hp
		}
	}
	return s
}

func stripScheme(hp string) string {
	if _, rest, ok := strings.Cut(hp, "://"); ok {
		return rest
	}
	return hp
}
