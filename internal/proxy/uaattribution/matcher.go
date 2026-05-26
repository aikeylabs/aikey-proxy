// Package uaattribution maps inbound HTTP User-Agent headers to a
// stable app_slug string, used as the "App" dimension in the usage-by-
// key dashboard for traffic that flows through the OAuth direct path
// (/v1/...).
//
// Background. Connected Apps that enter via /apps/<slug>/v1/... carry
// the slug explicitly in the URL — no inference needed. The OAuth
// direct path has no such anchor, so without UA inspection every
// session for a given user collapses into rows that look identical in
// the UI (same email, different vk_id). See:
//
//   - workflow/CI/requirements/2026-05-26-usage-by-key-app-attribution.md
//   - workflow/CI/bugfix/20260526-usage-by-key-duplicate-rows-by-app-attribution.md
//
// Trust model. UA is client-controlled and trivially spoofable. The
// attribution this package produces never affects routing, auth, or
// billing — it is a display-only signal feeding the per-app dashboard.
// Treat the output as advisory.
//
// Failure mode. Bad embedded YAML is a build-time / boot-time error:
// MustLoad panics so we fail loud rather than silently degrading every
// OAuth event to "unknown-app". Matchers built from invalid config are
// never returned.
package uaattribution

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed ua-fingerprint.yaml
var embeddedFingerprintYAML []byte

// rule is one prefix → slug mapping entry from ua-fingerprint.yaml.
type rule struct {
	Prefix string `yaml:"prefix"`
	Slug   string `yaml:"slug"`
}

// fingerprintFile mirrors the on-disk YAML schema.
type fingerprintFile struct {
	Rules        []rule `yaml:"rules"`
	FallbackSlug string `yaml:"fallback_slug"`
}

// Matcher resolves a raw User-Agent header to an app_slug.
//
// Construction is cheap and the resulting Matcher is safe for
// concurrent use. Callers should reuse a single Matcher per process
// (see Default).
type Matcher struct {
	rules    []rule
	fallback string
}

// Match returns the app_slug for the given raw User-Agent header.
//
// Matching is case-sensitive prefix; the first rule that matches wins.
// An empty input or no matching rule returns the configured fallback
// (never the empty string — see ua-fingerprint.yaml rationale).
func (m *Matcher) Match(userAgent string) string {
	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		return m.fallback
	}
	for _, r := range m.rules {
		if r.Prefix != "" && strings.HasPrefix(ua, r.Prefix) {
			return r.Slug
		}
	}
	return m.fallback
}

// Load parses raw YAML bytes into a Matcher.
//
// Used directly only by tests; production code calls Default which
// caches the matcher built from the embedded ua-fingerprint.yaml.
func Load(raw []byte) (*Matcher, error) {
	var f fingerprintFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("uaattribution: parse fingerprint yaml: %w", err)
	}
	if strings.TrimSpace(f.FallbackSlug) == "" {
		return nil, fmt.Errorf("uaattribution: fallback_slug must be non-empty")
	}
	for i, r := range f.Rules {
		if strings.TrimSpace(r.Prefix) == "" {
			return nil, fmt.Errorf("uaattribution: rule %d: prefix must be non-empty", i)
		}
		if strings.TrimSpace(r.Slug) == "" {
			return nil, fmt.Errorf("uaattribution: rule %d: slug must be non-empty", i)
		}
	}
	return &Matcher{rules: f.Rules, fallback: f.FallbackSlug}, nil
}

var (
	defaultOnce sync.Once
	defaultM    *Matcher
)

// Default returns the process-wide Matcher built from the embedded
// ua-fingerprint.yaml. The first call parses; subsequent calls return the
// cached instance. Panics if the embedded YAML is malformed (boot-time
// build break — see package docstring "Failure mode").
func Default() *Matcher {
	defaultOnce.Do(func() {
		m, err := Load(embeddedFingerprintYAML)
		if err != nil {
			panic(fmt.Sprintf("uaattribution: embedded ua-fingerprint.yaml is invalid: %v", err))
		}
		defaultM = m
	})
	return defaultM
}
