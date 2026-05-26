package uaattribution

import (
	"strings"
	"testing"
)

func TestDefaultLoads(t *testing.T) {
	// Boot-time invariant: embedded ua-fingerprint.yaml must always parse
	// cleanly. If a future edit corrupts the YAML this test catches it
	// in CI rather than at proxy startup.
	m := Default()
	if m == nil {
		t.Fatal("Default() returned nil")
	}
	if m.fallback != "unknown-app" {
		t.Fatalf("fallback want unknown-app, got %q", m.fallback)
	}
}

func TestMatch(t *testing.T) {
	m := Default()

	cases := []struct {
		name string
		ua   string
		want string
	}{
		{"empty UA → fallback", "", "unknown-app"},
		{"whitespace-only UA → fallback", "   ", "unknown-app"},
		{"claude-cli prefix", "claude-cli/2.1.22 (external, cli)", "claude-code"},
		{"claude-cli edge case bare prefix", "claude-cli/", "claude-code"},
		{"cursor lowercase", "cursor/0.41.3 (Mac)", "cursor"},
		{"cursor capitalized", "Cursor/0.41.3", "cursor"},
		{"cline lowercase", "cline/3.0.1", "cline"},
		{"Cline capitalized", "Cline/3.0.1", "cline"},
		{"codex prefix", "codex/1.0.0", "codex"},
		{"unknown UA → fallback", "FooBar/1.0", "unknown-app"},
		{"Mozilla browser → fallback", "Mozilla/5.0 (Macintosh)", "unknown-app"},
		// Prefix match is anchored at start — a substring match must NOT win.
		{"substring not at start → fallback", "wrapper claude-cli/x.y", "unknown-app"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.Match(tc.ua)
			if got != tc.want {
				t.Errorf("Match(%q) = %q, want %q", tc.ua, got, tc.want)
			}
		})
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "empty fallback",
			yaml: `rules: []
fallback_slug: ""`,
			want: "fallback_slug must be non-empty",
		},
		{
			name: "empty prefix in rule",
			yaml: `rules:
  - prefix: ""
    slug: "foo"
fallback_slug: "unknown-app"`,
			want: "prefix must be non-empty",
		},
		{
			name: "empty slug in rule",
			yaml: `rules:
  - prefix: "foo/"
    slug: ""
fallback_slug: "unknown-app"`,
			want: "slug must be non-empty",
		},
		{
			name: "malformed yaml",
			yaml: `rules: [`,
			want: "parse fingerprint yaml",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v; want substring %q", err, tc.want)
			}
		})
	}
}

func TestMatchFirstRuleWins(t *testing.T) {
	// Documenting the in-order match contract: if two rules have
	// overlapping prefixes the earlier-declared one wins. This matters
	// for future maintainers adding rules — order is part of the
	// contract, not just for aesthetics.
	cfg := `rules:
  - prefix: "foo/"
    slug: "winner"
  - prefix: "foo/bar"
    slug: "loser"
fallback_slug: "unknown-app"`

	m, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := m.Match("foo/bar/baz"); got != "winner" {
		t.Errorf("Match(foo/bar/baz) = %q, want winner (first rule wins)", got)
	}
}
