package apppipe

import (
	"testing"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
)

// Phase 2 Day 7 URL redesign: the URL `<protocol>` segment was removed;
// inbound shape is `/apps/<slug>/v1/...` and the upstream is inferred
// from body.model at request time. See router.go's package doc for
// background.

// TestExtractAppPath_HappyPaths pins the canonical 3-segment + rest shape.
// These are the inputs the App pipeline must accept in production.
func TestExtractAppPath_HappyPaths(t *testing.T) {
	cases := []struct {
		path             string
		wantSlug         string
		wantStrippedPath string
	}{
		{
			path:             "/apps/degrade-detector/v1/chat/completions",
			wantSlug:         "degrade-detector",
			wantStrippedPath: "/chat/completions",
		},
		{
			path:             "/apps/agent-x/v1/embeddings",
			wantSlug:         "agent-x",
			wantStrippedPath: "/embeddings",
		},
		{
			// Deep nested upstream path — SplitN(N=4) must NOT chop further
			// than the v1 segment; the rest is preserved verbatim.
			path:             "/apps/a/v1/chat/completions/streaming/long",
			wantSlug:         "a",
			wantStrippedPath: "/chat/completions/streaming/long",
		},
		{
			// Just /v1 with no rest — should yield "/" so callers can
			// concatenate without nil checks.
			path:             "/apps/agent/v1",
			wantSlug:         "agent",
			wantStrippedPath: "/",
		},
		{
			// Trailing slash with no rest — same as the no-trailing-slash case.
			path:             "/apps/agent/v1/",
			wantSlug:         "agent",
			wantStrippedPath: "/",
		},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got := ExtractAppPath(c.path)
			if got == nil {
				t.Fatalf("ExtractAppPath(%q) = nil, want non-nil", c.path)
			}
			if got.Slug != c.wantSlug {
				t.Errorf("Slug = %q, want %q", got.Slug, c.wantSlug)
			}
			if got.StrippedPath != c.wantStrippedPath {
				t.Errorf("StrippedPath = %q, want %q", got.StrippedPath, c.wantStrippedPath)
			}
		})
	}
}

// TestExtractAppPath_NonMatchingReturnsNil pins the negative space —
// the legacy /v1/... and /<provider>/v1/... entries MUST NOT match this
// parser (otherwise they'd be incorrectly dispatched to the App pipeline,
// breaking the existing personal/team/oauth flow).
func TestExtractAppPath_NonMatchingReturnsNil(t *testing.T) {
	cases := []struct {
		path string
		why  string
	}{
		// Wrong prefix.
		{"/openai/v1/chat", "legacy provider-prefix routing"},
		{"/anthropic/v1/messages", "legacy provider-prefix routing"},
		{"/v1/chat/completions", "legacy /v1 entry"},
		{"/api/v1/chat", "unrelated path"},
		{"/", "root path"},
		{"", "empty path"},

		// /apps/ but malformed.
		{"/apps", "no trailing slash, just literal /apps"},
		{"/apps/", "missing all remaining segments"},
		{"/apps/X", "only slug, missing v1"},

		// Phase 1 URL form — must NOT match Phase 2 router. Old form
		// `/apps/<slug>/<protocol>/v1/...` had 4 segments; the new form
		// is 3. Clients still pointing at the old URL should see a clean
		// 404 (caller falls through to legacy provider routing, which
		// will also reject — that's fine).
		{"/apps/X/openai/v1/chat", "Phase 1 URL form (with <protocol> segment) — Phase 2 router rejects"},
		{"/apps/X/anthropic/v1/messages", "Phase 1 URL form — rejected"},

		// Wrong version segment.
		{"/apps/X/v2/foo", "v2 — only v1 is supported today"},
		{"/apps/X/v3", "v3"},
		{"/apps/X/v0/foo", "v0"},
		{"/apps/X/V1/foo", "uppercase V1 — case-sensitive routing"},
		{"/apps/X/", "missing version segment entirely"},

		// Easy to misread — apps as some other path segment.
		{"/v1/apps/X/openai", "apps as a path component but not at root"},
		{"/foo/apps/X/v1", "apps in middle of path"},
		{"/myapps/X/v1", "prefix substring apps but different segment"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := ExtractAppPath(c.path); got != nil {
				t.Errorf("ExtractAppPath(%q) = %+v, want nil (%s)", c.path, got, c.why)
			}
		})
	}
}

// TestExtractAppPath_AcceptsAnySlugString documents the
// deliberate-no-validation contract from the AppContext doc: router
// is the SYNTACTIC boundary, semantic validation lives downstream.
// If a future refactor adds slug allowlisting here, downstream error
// codes (APP_NOT_FOUND) would lose precision.
func TestExtractAppPath_AcceptsAnySlugString(t *testing.T) {
	got := ExtractAppPath("/apps/Invalid_SLUG.123/v1/x")
	if got == nil {
		t.Fatal("router must not validate slug semantically; downstream does")
	}
	if got.Slug != "Invalid_SLUG.123" {
		t.Errorf("verbatim passthrough wrong: %+v", got)
	}
}

// TestExtractAppPath_SlugCanCollideWithProviderName is the regression for
// the ordering invariant — /apps/openai/v1/... has slug='openai' which
// would crash if anything mistook it for the legacy /<provider>/v1/...
// pattern. Router parsing must succeed; the ordering check (router-first,
// then provider-prefix) is enforced by the proxy.Handle wiring (AKL-208).
func TestExtractAppPath_SlugCanCollideWithProviderName(t *testing.T) {
	got := ExtractAppPath("/apps/openai/v1/chat")
	if got == nil {
		t.Fatal("slug='openai' must parse; provider-name collision is a wiring concern not a router concern")
	}
	if got.Slug != "openai" {
		t.Errorf("got %+v", got)
	}
	if got.StrippedPath != "/chat" {
		t.Errorf("StrippedPath = %q, want /chat", got.StrippedPath)
	}
}

// ─── InferInboundWire (Phase 2 中方案, 2026-05-21) ─────────────────────

// TestInferInboundWire_HappyPaths pins the wire-format detection. URL
// path is the authoritative signal (SDK choice hardcodes path).
func TestInferInboundWire_HappyPaths(t *testing.T) {
	cases := []struct {
		strippedPath string
		want         translator.Format
		why          string
	}{
		// OpenAI wire (default for any non-/messages path)
		{"/chat/completions", translator.FormatOpenAI, "openai-python / ChatOpenAI"},
		{"/embeddings", translator.FormatOpenAI, "OpenAI embeddings (passthrough)"},
		{"/audio/speech", translator.FormatOpenAI, "OpenAI audio (passthrough)"},
		{"/", translator.FormatOpenAI, "empty rest defaults to OpenAI"},
		{"/chat/completions/streaming/long", translator.FormatOpenAI, "deep nested chat path"},

		// Anthropic wire (single canonical path)
		{"/messages", translator.FormatAnthropic, "anthropic-python / ChatAnthropic / Claude Code / Cursor"},
		{"/v1/messages", translator.FormatAnthropic, "raw HTTP that mistakenly kept /v1 prefix - still matches by suffix"},

		// Edge: empty string falls to default
		{"", translator.FormatOpenAI, "empty string is OpenAI default"},
	}
	for _, c := range cases {
		t.Run(c.strippedPath, func(t *testing.T) {
			got := InferInboundWire(c.strippedPath)
			if got != c.want {
				t.Errorf("InferInboundWire(%q) = %q, want %q (%s)",
					c.strippedPath, got, c.want, c.why)
			}
		})
	}
}

// TestInferInboundWire_PathWithMessagesSubstring_StillMatchesByCorrectSuffix
// guards against false-positives where "messages" appears mid-path. The
// HasSuffix check guarantees we only match the canonical trailing form.
func TestInferInboundWire_PathWithMessagesSubstring_StillMatchesByCorrectSuffix(t *testing.T) {
	// "/messages/list" has "messages" in it but is not the Anthropic
	// Messages endpoint. Must classify as OpenAI default (the path is
	// unknown but defaults safely; downstream will 404 / 405 at the
	// upstream rather than mis-translate).
	if got := InferInboundWire("/messages/list"); got != translator.FormatOpenAI {
		t.Errorf(`/messages/list classified as %q, want OpenAI default (HasSuffix prevents false match)`, got)
	}
}
