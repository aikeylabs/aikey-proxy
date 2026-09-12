package proxy

import "testing"

// OAuth dialect gate (2026-07-13, user report: codex works but opencode dies
// with "invalid x-api-key").
//
// Codex is the ONE provider whose OAuth upstream differs from its API-key
// upstream: ChatGPT accounts are served by chatgpt.com/backend-api/codex, which
// speaks only the Responses API. The request path is appended verbatim to that
// base, so a /chat/completions client (opencode, ai-sdk, LangChain, …) hit a
// route that doesn't exist there and got ChatGPT's edge 4xx — whose body claims
// the API key is invalid. The key was fine; the dialect wasn't.
//
// These pin the predicate: reject non-/responses paths on the openai-OAuth lane
// ONLY, and never constrain any other provider (whose OAuth upstream == its
// API-key upstream).

func TestOAuthUpstreamRejectsPath_CodexResponsesOnly(t *testing.T) {
	cases := []struct {
		name       string
		canonical  string
		path       string
		wantReject bool
	}{
		// The lane that broke: opencode / ai-sdk speak Chat Completions.
		{"openai oauth + chat/completions → reject", "openai", "/v1/chat/completions", true},
		{"openai oauth + group-lane chat/completions → reject", "openai", "/chat/completions", true},
		{"openai oauth + completions (legacy) → reject", "openai", "/v1/completions", true},
		{"openai oauth + embeddings → reject", "openai", "/v1/embeddings", true},

		// The lane that works: codex speaks Responses.
		{"openai oauth + /v1/responses → allow", "openai", "/v1/responses", false},
		{"openai oauth + group-lane /responses → allow", "openai", "/responses", false},
		{"openai oauth + trailing slash → allow", "openai", "/v1/responses/", false},

		// 🔴 The codex backend serves MORE than /responses, and refusing these
		// was our bug, not the upstream's limit (2026-09-10). Each line below is
		// a path a codex client was observed calling DIRECTLY against
		// chatgpt.com/backend-api/codex and getting 200 — so a refusal here is
		// AiKey inventing a failure the upstream would not have produced.
		//
		// /models is the expensive one: codex probes it before it will use a
		// provider at all, so refusing it stopped the client at discovery and
		// no /responses call was ever attempted (live cluster: 7 probes, 0
		// /responses). /images/edits is how codex generates images; refusing it
		// is why "图像服务返回 401" had no working answer.
		{"openai oauth + models (codex probes this first) → allow", "openai", "/v1/models", false},
		{"openai oauth + group-lane models → allow", "openai", "/models", false},
		{"openai oauth + images/edits (codex image tool) → allow", "openai", "/v1/images/edits", false},
		{"openai oauth + group-lane images/edits → allow", "openai", "/images/edits", false},
		{"openai oauth + images/generations → allow", "openai", "/v1/images/generations", false},

		// Every other provider's OAuth upstream == its API-key upstream: no gate.
		{"anthropic oauth + messages → allow", "anthropic", "/v1/messages", false},
		{"kimi oauth + chat/completions → allow", "kimi", "/v1/chat/completions", false},
		{"empty provider → allow (don't block on unknown)", "", "/v1/chat/completions", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason := oauthUpstreamRejectsPath(c.canonical, c.path)
			if c.wantReject && reason == "" {
				t.Fatalf("expected rejection for %s %s", c.canonical, c.path)
			}
			if !c.wantReject && reason != "" {
				t.Fatalf("expected pass for %s %s, got rejection: %s", c.canonical, c.path, reason)
			}
		})
	}
}

func TestOAuthUpstreamRejectsPath_ReasonIsActionable(t *testing.T) {
	// The whole point of the gate is that the user learns (a) what is actually
	// wrong and (b) how to fix it — the upstream's "invalid x-api-key" gave
	// neither.
	reason := oauthUpstreamRejectsPath("openai", "/v1/chat/completions")
	if reason == "" {
		t.Fatal("expected a rejection reason")
	}
	for _, want := range []string{"Responses API", "/v1/chat/completions", "API-key credential"} {
		if !contains(reason, want) {
			t.Fatalf("reason must mention %q, got: %s", want, reason)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
