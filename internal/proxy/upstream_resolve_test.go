package proxy

import (
	"os"
	"regexp"
	"testing"
)

// 🔴 「展示=执行」 fence (requirements/2026-07-18 §上游地址单一解析, rule 2).
//
// The spec says the address we show/probe must be byte-identical to the one we
// forward to, computed by 「同一个解析函数」, and that manufacturing a second
// fallback 「应导致围栏变红」. That fence did not exist, which is why the probe
// path drifted for months without anyone noticing.
//
// This is a SOURCE scan rather than a value comparison on purpose. A value test
// can only prove the two agree on the inputs the test happens to pick; the
// defect here was structural — a parallel copy of the precedence ladder living
// in another file. Scanning for the ladder catches the re-introduction itself.
func TestUpstreamPrecedenceLadderHasExactlyOneImplementation(t *testing.T) {
	// The shape that drifted: a chain that falls back to providerDefaultBaseURL
	// after testing an entry-supplied address. Outside the shared resolver, no
	// file may contain it.
	ladder := regexp.MustCompile(`(?s)entryBaseURL[^\n]*\n.{0,400}?providerDefaultBaseURL`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !regexp.MustCompile(`\.go$`).MatchString(name) {
			continue
		}
		if name == "upstream_resolve.go" || name == "upstream_resolve_test.go" {
			continue // the one legitimate home
		}
		src, rerr := os.ReadFile(name)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		if ladder.Match(src) {
			t.Errorf("%s re-implements the upstream precedence ladder. Two copies is exactly the "+
				"split requirements/2026-07-18 forbids: the probe and the forwarder would answer "+
				"different addresses for the same key, and the probe's verdict stops meaning "+
				"anything about the credential under test. Call ResolvePersonalUpstreamBase.", name)
		}
	}
}

// The forwarding path must actually CALL the shared resolver — deleting the call
// and inlining the ladder again is the regression this pairs with above.
func TestForwardingPathCallsTheSharedResolver(t *testing.T) {
	src, err := os.ReadFile("pipelines.go")
	if err != nil {
		t.Fatalf("read pipelines.go: %v", err)
	}
	if !regexp.MustCompile(`ResolvePersonalUpstreamBase\(`).Match(src) {
		t.Error("the Tier2Probe sentinel branch no longer calls ResolvePersonalUpstreamBase — " +
			"if the forwarder stops using the shared resolver, the probe is testing an address " +
			"nothing forwards to, which is the 2026-08-03 bug in reverse")
	}
}

// Precedence itself, pinned. Each rung exists for a reason recorded in the
// resolver's doc comment; a silent reorder changes which upstream real traffic
// reaches.
func TestResolvePersonalUpstreamBase_Precedence(t *testing.T) {
	const custom = "http://120.24.220.105:18080/oauth_group/anthropic/abc"

	// 🔴 The entry's own address wins outright — this is the case the probe used
	// to throw away, and it is not exotic: self-hosted gateways and OAuth
	// ingresses are the whole reason base_url is user-settable.
	if got := ResolvePersonalUpstreamBase(custom, "anthropic", "anthropic"); got != custom {
		t.Errorf("custom base_url must win outright, got %q", got)
	}

	// With no custom address, the ENTRY's provider decides — not the path.
	// A multi-provider alias would otherwise be resolved by whichever prefix the
	// client happened to use.
	byEntry := ResolvePersonalUpstreamBase("", "anthropic", "openai")
	byPath := ResolvePersonalUpstreamBase("", "", "openai")
	if byEntry == "" || byPath == "" {
		t.Skip("provider routes unavailable in this build; precedence order still asserted above")
	}
	if byEntry == byPath {
		t.Errorf("entry provider_code was ignored: entry-resolved %q == path-resolved %q", byEntry, byPath)
	}

	// An entry naming a provider with NO route row must fall through to the
	// path-derived provider rather than returning empty — the rung that keeps a
	// stale provider_code from making a working key unroutable.
	if got := ResolvePersonalUpstreamBase("", "no-such-provider-xyz", "openai"); got != byPath {
		t.Errorf("unknown entry provider must fall through to the path-derived default; got %q want %q", got, byPath)
	}
}
