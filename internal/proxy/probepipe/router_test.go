package probepipe

import "testing"

// TestExtractProbePath exercises the URL parser for the Probe pipeline.
// Mirrors the structure of apppipe/router_test.go::TestExtractAppPath so a
// future reader recognizes the pattern immediately.
func TestExtractProbePath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantAlias  string
		wantStrip  string
		wantNil    bool
	}{
		// Happy path — Anthropic /messages tail.
		{
			name:      "anthropic_messages",
			path:      "/probe/myalias/v1/messages",
			wantAlias: "myalias",
			wantStrip: "/messages",
		},
		// Happy path — OpenAI /chat/completions tail.
		{
			name:      "openai_chat_completions",
			path:      "/probe/myalias/v1/chat/completions",
			wantAlias: "myalias",
			wantStrip: "/chat/completions",
		},
		// /probe/<alias>/v1 with no tail → StrippedPath "/".
		{
			name:      "no_tail",
			path:      "/probe/myalias/v1",
			wantAlias: "myalias",
			wantStrip: "/",
		},
		// Trailing slash equivalent to no tail.
		{
			name:      "trailing_slash",
			path:      "/probe/myalias/v1/",
			wantAlias: "myalias",
			wantStrip: "/",
		},
		// OAuth email alias — "@" allowed unencoded by SPEC charset.
		{
			name:      "oauth_email_unencoded",
			path:      "/probe/user@host.com/v1/messages",
			wantAlias: "user@host.com",
			wantStrip: "/messages",
		},
		// OAuth email alias — percent-encoded "@" must decode.
		{
			name:      "oauth_email_percent_encoded",
			path:      "/probe/user%40host.com/v1/messages",
			wantAlias: "user@host.com",
			wantStrip: "/messages",
		},
		// Personal alias with dot and hyphen — all SPEC charset.
		{
			name:      "personal_alias_dot_hyphen",
			path:      "/probe/my-claude.key_2/v1/messages",
			wantAlias: "my-claude.key_2",
			wantStrip: "/messages",
		},
		// ── Negative cases ────────────────────────────────────────────────
		{
			name:    "missing_v1",
			path:    "/probe/myalias",
			wantNil: true,
		},
		{
			name:    "wrong_version",
			path:    "/probe/myalias/v2/messages",
			wantNil: true,
		},
		{
			name:    "apps_prefix_not_probe",
			path:    "/apps/myalias/v1/messages",
			wantNil: true,
		},
		{
			name:    "no_alias",
			path:    "/probe//v1/messages",
			wantNil: true,
		},
		{
			name:    "empty_path",
			path:    "/",
			wantNil: true,
		},
		// Charset enforcement — "/" not allowed in a single alias segment
		// (it splits the URL); slash never reaches isValidAliasName, but
		// any other forbidden character does.
		{
			name:    "charset_space_forbidden",
			path:    "/probe/my%20alias/v1/messages", // decodes to "my alias"
			wantNil: true,
		},
		{
			name:    "charset_plus_forbidden",
			path:    "/probe/my+alias/v1/messages",
			wantNil: true,
		},
		{
			name:    "charset_colon_forbidden",
			path:    "/probe/my:alias/v1/messages",
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractProbePath(tc.path)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("path %q: expected nil, got %+v", tc.path, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("path %q: expected ProbeContext, got nil", tc.path)
			}
			if got.AliasName != tc.wantAlias {
				t.Errorf("AliasName: got %q, want %q", got.AliasName, tc.wantAlias)
			}
			if got.StrippedPath != tc.wantStrip {
				t.Errorf("StrippedPath: got %q, want %q", got.StrippedPath, tc.wantStrip)
			}
		})
	}
}

// TestExtractProbePath_DoesNotInterceptApps is the routing-precedence
// invariant: ExtractProbePath must NEVER return non-nil for an /apps/<slug>
// URL, otherwise the apppipe path would be silently broken when added to
// the router chain in proxy.Handle.
func TestExtractProbePath_DoesNotInterceptApps(t *testing.T) {
	cases := []string{
		"/apps/degrade-detector/v1/messages",
		"/apps/foo/v1",
		"/apps/anything/v1/chat/completions",
	}
	for _, p := range cases {
		if got := ExtractProbePath(p); got != nil {
			t.Errorf("path %q must not match probe (got %+v)", p, got)
		}
	}
}
