// Package apppipe implements the App pipeline — the request path for
// third-party Agent applications routed via /apps/<slug>/v1/... URLs
// (Phase 4 第三方 Agent 接入).
//
// Pipeline layout (built across multiple sub-tasks):
//
//   router.go    — URL parsing (this file)
//   authn.go     — Bearer token validation + slug cross-check
//   resolve.go   — profile_id decision + binding lookup by inferred upstream
//   egress.go    — request body sanitizer (strip X-AiKey-* / body.aikey /
//                  metadata, hard-rejects, etc.)
//   translate.go — protocol translator engagement (body.model → upstream,
//                  set ResolvedRoute.ResponseTransform, path canonicalization)
//   pipeline.go  — top-level orchestrator: authn → resolve → sanitize →
//                  translate → forward upstream → SSE passthrough → emit
//                  usage event
//
// 2026-05-21 Phase 2 Day 7 URL redesign:
//
// The URL `<protocol>` segment that lived between <slug> and v1 in Phase 1
// (`/apps/<slug>/<protocol>/v1/...`) was REMOVED in favor of inferring
// the upstream from body.model at request time. Background: LangChain
// research confirmed that "protocol via URL segment" is non-standard
// (LiteLLM / OpenRouter / Kong all route via body.model field, never URL
// path); keeping it forced users to make a redundant routing decision
// that the Agent's body already encodes implicitly via the model name.
// See `roadmap20260320/技术实现/protocol-translator/langchain-wire-protocol-research.md`.
//
// Inbound wire format is ALWAYS OpenAI Chat Completions at阶段 0 — the
// URL is fixed at `/apps/<slug>/v1/chat/completions`. Cross-protocol
// (e.g., body.model=claude-3-5-sonnet → upstream=Anthropic) is handled by
// the translator after resolve.
//
// Why a separate package: keeps the App pipeline's contracts and helpers
// isolated from the legacy /v1/... and /<provider>/v1/... pipelines in
// proxy/proxy.go, so the two paths can evolve independently. proxy.Handle
// detects /apps/ URLs first (Tier 0a, AKL-208) and dispatches into here;
// nothing in this package depends on proxy/proxy.go's internals, so
// changes here don't risk regressing the legacy path.
package apppipe

import (
	"strings"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
)

// AppContext is the parsed shape of an /apps/<slug>/v1/... URL.
//
// Slug is NOT validated semantically by this layer (no charset /
// app_records existence check) — that's intentional. router.go is the
// pure-syntactic boundary; downstream stages produce precise error codes:
//   - authn.go    — APP_NOT_FOUND / APP_KEY_REVOKED / APP_MISMATCH
//   - resolve.go  — UPSTREAM_UNINFERRABLE / UPSTREAM_NOT_DECLARED / BINDING_NOT_FOUND
type AppContext struct {
	// Slug is the path segment between /apps/ and /v1/, matched
	// against app_records.slug at the auth layer.
	Slug string
	// StrippedPath is what the upstream sees: the remainder after
	// /apps/<slug>/v1. Always starts with "/", so it's safe to
	// concatenate with upstream BaseURL + "/v1" to reconstruct the
	// upstream target. Typical values: "/chat/completions",
	// "/embeddings", etc.
	StrippedPath string
}

// ExtractAppPath parses an HTTP request path and returns an AppContext
// iff the path matches /apps/<slug>/v1[/<rest>]. Otherwise returns nil
// — caller should fall through to the legacy proxy pipelines.
//
// Edge cases:
//   - /apps/X/v1            → {Slug:X, StrippedPath:"/"}
//   - /apps/X/v1/           → same (trailing slash collapses)
//   - /apps/X/v1/chat/completions → {Slug:X, StrippedPath:"/chat/completions"}
//   - /apps                 → nil
//   - /apps/                → nil
//   - /apps/X               → nil (missing v1)
//   - /apps/X/Y             → nil (Y is not "v1"; reject — Phase 1 used
//                             /apps/<slug>/<protocol>/v1/ which Phase 2
//                             Day 7 removed)
//   - /apps/X/v2/foo        → nil (v1 only — bump explicitly when /v2 lands)
//   - /openai/v1/chat       → nil (legacy provider-prefix routing)
//   - /v1/chat              → nil (legacy entry)
//
// CRITICAL: caller MUST invoke this BEFORE the legacy
// extractProviderFromPath check in proxy.Handle, otherwise
// /apps/X/v1 would be misread by an over-eager parser. The ordering
// invariant is enforced by AKL-208 with a dedicated regression test.
//
// Phase 1 URL backward compatibility: NONE. Phase 1 was pre-GA testers
// only; per CLAUDE.md's pre-GA "uninstall + reinstall" policy, existing
// dev users re-authorize and pick up the new URL. The Day 7 design doc
// elaborates.
// InferInboundWire decides the inbound wire format from the URL's
// stripped-path tail. SDK choice hardcodes the path so this is the
// authoritative signal (see Phase 2 中方案 design doc:
// `roadmap20260320/技术实现/update/20260521-Anthropic入站passthrough-中方案.md`).
//
// Mapping:
//   - "/v1/messages"  → Anthropic wire (anthropic-python / ChatAnthropic /
//                       Claude Code / Cursor Anthropic endpoint)
//   - "/messages"     → Anthropic wire (after the /apps/<slug>/v1 prefix
//                       is stripped, the tail begins at /messages)
//   - anything else   → OpenAI wire (default — covers /chat/completions,
//                       /embeddings, and any future OpenAI-compatible path)
//
// Why default to OpenAI: the OpenAI Chat Completions API has the broadest
// surface area (chat / embeddings / images / audio); other SDK paths that
// the App pipeline forwards are all OpenAI-compatible derivatives.
// Anthropic's Messages API has exactly one path so a precise check works.
//
// Empty string returns FormatOpenAI for safety — caller treats the no-path
// edge case as the dominant inbound type.
func InferInboundWire(strippedPath string) translator.Format {
	// strippedPath is what's after /apps/<slug>/v1; typical values:
	//   "/chat/completions"   → OpenAI
	//   "/messages"           → Anthropic
	//   "/embeddings"         → OpenAI (passthrough; no translation in Phase 0)
	//   "/" (no rest)         → OpenAI default
	if strings.HasSuffix(strippedPath, "/messages") {
		return translator.FormatAnthropic
	}
	return translator.FormatOpenAI
}

func ExtractAppPath(path string) *AppContext {
	// Tolerate a leading slash; split into at most 4 parts so the rest
	// after /apps/<slug>/v1/ is collected intact (including any further
	// '/' separators in the upstream's own URL).
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 4)
	if len(parts) < 3 || parts[0] != "apps" {
		return nil
	}
	if parts[2] != "v1" {
		return nil
	}
	// parts[1] = slug, parts[2] = "v1", parts[3] (if present) = the rest.
	rest := "/"
	if len(parts) == 4 {
		// "/foo/bar" — re-add the leading slash SplitN stripped. Empty
		// parts[3] (trailing slash case: /apps/X/v1/) still yields "/",
		// matching the no-rest case for caller convenience.
		if parts[3] == "" {
			rest = "/"
		} else {
			rest = "/" + parts[3]
		}
	}
	return &AppContext{
		Slug:         parts[1],
		StrippedPath: rest,
	}
}
