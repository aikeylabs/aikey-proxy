// Package sessionid maps an inbound HTTP request to a stable session_id
// string, used as the per-conversation aggregation dimension in the
// usage-by-session dashboard.
//
// Background. Different protocols and different clients carry the
// session ID in different places — Claude Code stamps a header
// (X-Claude-Code-Session-Id), Kimi uses a body field (prompt_cache_key),
// OpenAI's ChatGPT API uses body (conversation_id). Hard-coding a
// per-protocol switch would calcify the proxy; new protocols would
// need a code change and a redeploy. Instead, session-fingerprint.yaml lists
// (protocol, provider) → ordered source candidates, and this package
// loads it at boot. See:
//
//   - roadmap20260320/技术实现/阶段5-丰富生态/20260526-Performance页会话维度与下钻设计.md
//   - roadmap20260320/技术实现/阶段5-丰富生态/20260526-Performance页会话维度-分阶段实施计划.md
//
// Trust model. session_id is client-controlled and trivially spoofable.
// It only feeds display dashboards; routing, auth, and billing never
// consult it. Same trust posture as uaattribution.
//
// Failure mode. Malformed embedded yaml panics at first call to Default
// — boot-time fail-loud rather than silently degrading every event to
// "no session". A request whose body can't be parsed as JSON, or whose
// body exceeds body_max_bytes, gracefully returns empty from the body
// source (no panic, header sources continue to work).
package sessionid

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed session-fingerprint.yaml
var embeddedFingerprintYAML []byte

// Source types — kept as string constants (not iota int) so yaml
// validation errors quote the actual offending value, easier debugging.
const (
	SourceTypeHeader        = "header"
	SourceTypeBodyJSONField = "body_json_field"
)

type matchCriteria struct {
	Protocol string `yaml:"protocol"`
	Provider string `yaml:"provider,omitempty"` // empty == any provider for this protocol
}

type source struct {
	Type string `yaml:"type"`           // "header" | "body_json_field"
	Name string `yaml:"name,omitempty"` // for header
	Path string `yaml:"path,omitempty"` // for body_json_field; dot-separated, one level of nesting supported
}

type rule struct {
	Match   matchCriteria `yaml:"match"`
	Sources []source      `yaml:"sources"`
}

type fingerprintFile struct {
	Rules          []rule   `yaml:"rules"`
	CommonFallback []source `yaml:"common_fallback"`
	BodyMaxBytes   int      `yaml:"body_max_bytes"`
}

// Matcher resolves an inbound request to a session_id string.
//
// Cheap to construct, safe for concurrent use. Production code should
// reuse the process-wide Default() instance.
type Matcher struct {
	rules          []rule
	commonFallback []source
	bodyMaxBytes   int
}

// Extract returns the session_id for the given request, scoped to the
// (protocol, provider) the caller has already resolved via routing.
//
// Matching order: walk rules in declared order, stop on first rule
// whose match block fits. Within that rule, walk sources in declared
// order, stop on first non-empty extraction. If no rule matches, OR
// the matching rule's sources all return empty, fall back to
// commonFallback sources. If everything returns empty, return "".
//
// Body parsing (body_json_field source) is opt-in per rule — adding a
// body source means the request body is read into memory up to
// bodyMaxBytes and parsed as JSON. The body is reset on req so
// downstream readers see the original stream. Requests with body
// larger than bodyMaxBytes skip the JSON parse step (returns empty
// from the body source; header sources continue to work).
//
// Caller contract: protocol must be one of the values the proxy uses
// internally (e.g. "anthropic", "openai", "openai_compatible"); empty
// protocol is treated as no-match against per-protocol rules but
// commonFallback still applies.
func (m *Matcher) Extract(req *http.Request, protocol, provider string) string {
	if req == nil {
		return ""
	}
	// Per-protocol rule match (first wins).
	for _, r := range m.rules {
		if !ruleMatches(r.Match, protocol, provider) {
			continue
		}
		if v := m.trySources(req, r.Sources); v != "" {
			return v
		}
		// Rule matched but extracted nothing — fall through to fallback,
		// don't keep trying other per-protocol rules (the matched rule
		// is authoritative; another rule wouldn't have known better).
		break
	}
	// Common fallback (cheap header-only sources).
	if v := m.trySources(req, m.commonFallback); v != "" {
		return v
	}
	return ""
}

// trySources walks sources in order; first non-empty wins. Body parse
// state is cached across sources within a single call so multiple
// body_json_field probes on the same request don't re-parse JSON.
func (m *Matcher) trySources(req *http.Request, sources []source) string {
	if len(sources) == 0 {
		return ""
	}
	// Lazy body parse — only fires if a body_json_field source is hit
	// AND no earlier source already returned a value. Saves the cost
	// of body buffering on the happy path (header hit on first try).
	var bodyJSON map[string]any
	bodyParsed := false
	for _, s := range sources {
		switch s.Type {
		case SourceTypeHeader:
			if v := strings.TrimSpace(req.Header.Get(s.Name)); v != "" {
				return v
			}
		case SourceTypeBodyJSONField:
			if !bodyParsed {
				bodyJSON = m.parseBodyJSON(req) // returns nil on any failure (oversized, malformed, no body)
				bodyParsed = true
			}
			if bodyJSON == nil {
				continue
			}
			if v := lookupJSONPath(bodyJSON, s.Path); v != "" {
				return v
			}
		}
		// Unknown source types silently skipped — yaml validation in
		// Load() catches typos at boot, so reaching here would mean a
		// programmer added a new type without updating this switch.
	}
	return ""
}

// parseBodyJSON reads the request body up to bodyMaxBytes, parses as a
// flat JSON object, and resets req.Body so downstream handlers still
// see the original stream. Returns nil for any failure mode:
//   - no body / nil body
//   - body exceeds bodyMaxBytes (read-and-discard would be wasteful;
//     we don't even start)
//   - body is not parseable as a JSON object
//
// Caller doesn't distinguish failure reasons — the upper layer treats
// nil map identically to "no field found".
func (m *Matcher) parseBodyJSON(req *http.Request) map[string]any {
	if req.Body == nil {
		return nil
	}
	// Pre-flight: if Content-Length is set and exceeds the cap, don't
	// even start reading. Avoids buffering huge cached-prompt requests.
	if req.ContentLength > 0 && req.ContentLength > int64(m.bodyMaxBytes) {
		return nil
	}
	// Defensive read with hard cap. If actual body exceeds cap mid-read
	// we get a partial buffer; we still try to parse it (might happen
	// to succeed if the first object closes before the cap), but the
	// fallthrough nil return on parse error is the safety net.
	limited := io.LimitReader(req.Body, int64(m.bodyMaxBytes)+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil
	}
	// If we read MORE than the cap, body was oversized — reset and bail.
	// Reset by stitching the buffer back onto whatever's left of body.
	if len(buf) > m.bodyMaxBytes {
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), req.Body))
		return nil
	}
	// Normal path: replay the buffer as the new body so downstream sees
	// identical bytes. Original body is fully consumed at this point.
	req.Body = io.NopCloser(bytes.NewReader(buf))
	var parsed map[string]any
	if err := json.Unmarshal(buf, &parsed); err != nil {
		return nil
	}
	return parsed
}

// lookupJSONPath supports either a top-level key ("conversation_id")
// or one level of nesting ("metadata.user_id"). Returns "" for any
// missing path segment or non-string leaf value (we don't coerce
// numbers / bools to strings — those don't carry session-ID semantics
// in any protocol we support today).
//
// Deeper nesting could be added by splitting on "." and recursing,
// but every real-world session-ID field lives at depth ≤ 2 and the
// shallow form keeps the implementation auditable.
func lookupJSONPath(obj map[string]any, path string) string {
	if obj == nil || path == "" {
		return ""
	}
	parts := strings.SplitN(path, ".", 2)
	leaf, ok := obj[parts[0]]
	if !ok {
		return ""
	}
	if len(parts) == 1 {
		s, _ := leaf.(string)
		return strings.TrimSpace(s)
	}
	nested, ok := leaf.(map[string]any)
	if !ok {
		return ""
	}
	v, _ := nested[parts[1]].(string)
	return strings.TrimSpace(v)
}

// ruleMatches returns true if the rule's match block applies to the
// given (protocol, provider). Empty provider in the rule means
// "any provider for this protocol".
func ruleMatches(crit matchCriteria, protocol, provider string) bool {
	if crit.Protocol != protocol {
		return false
	}
	if crit.Provider != "" && crit.Provider != provider {
		return false
	}
	return true
}

// Load parses raw yaml bytes into a Matcher. Production code calls
// Default; this entry point is for tests + future config-overlay use.
func Load(raw []byte) (*Matcher, error) {
	var f fingerprintFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("sessionid: parse fingerprint yaml: %w", err)
	}
	if f.BodyMaxBytes <= 0 {
		return nil, fmt.Errorf("sessionid: body_max_bytes must be > 0")
	}
	// Validate every source has a non-empty discriminator. Catches
	// typos like `type: header` with no `name:` — the source would
	// silently match the empty header (which is itself "") and never
	// return anything.
	for i, r := range f.Rules {
		if strings.TrimSpace(r.Match.Protocol) == "" {
			return nil, fmt.Errorf("sessionid: rule %d: match.protocol must be non-empty", i)
		}
		for j, s := range r.Sources {
			if err := validateSource(s); err != nil {
				return nil, fmt.Errorf("sessionid: rule %d source %d (%s): %w", i, j, r.Match.Protocol, err)
			}
		}
	}
	for j, s := range f.CommonFallback {
		if err := validateSource(s); err != nil {
			return nil, fmt.Errorf("sessionid: common_fallback source %d: %w", j, err)
		}
	}
	return &Matcher{
		rules:          f.Rules,
		commonFallback: f.CommonFallback,
		bodyMaxBytes:   f.BodyMaxBytes,
	}, nil
}

func validateSource(s source) error {
	switch s.Type {
	case SourceTypeHeader:
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("header source missing name")
		}
	case SourceTypeBodyJSONField:
		if strings.TrimSpace(s.Path) == "" {
			return fmt.Errorf("body_json_field source missing path")
		}
	default:
		return fmt.Errorf("unknown source type %q (allowed: header, body_json_field)", s.Type)
	}
	return nil
}

var (
	defaultOnce sync.Once
	defaultM    *Matcher
)

// Default returns the process-wide Matcher built from the embedded
// session-fingerprint.yaml. First call parses; subsequent calls return the
// cached instance. Panics on malformed embedded yaml (boot-time
// fail-loud per package docstring).
func Default() *Matcher {
	defaultOnce.Do(func() {
		m, err := Load(embeddedFingerprintYAML)
		if err != nil {
			panic(fmt.Sprintf("sessionid: embedded session-fingerprint.yaml is invalid: %v", err))
		}
		defaultM = m
	})
	return defaultM
}
