package supervisor

import (
	"errors"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
)

// fakeRefreshTokenSource is a minimal vault stub so we can exercise
// buildCollectorCredentials without standing up SQLite + Argon2id.
type fakeRefreshTokenSource struct {
	token string
	err   error
}

func (f fakeRefreshTokenSource) GetPlatformRefreshToken() (string, error) {
	return f.token, f.err
}

// ── 2026-05-11 B4: collector credential bootstrap ─────────────────────
//
// These tests pin the contract that turns user.yaml's
// `proxy.events.collector_credentials.team` (B3) + vault's
// `platform_account.refresh_token` into a reporter-consumable
// events.Credential at proxy startup. Reporter behavior (the
// generated Credential's Bearer() semantics) is exercised separately
// in internal/events/credential_test.go — these tests only cover the
// wiring path.

// Happy path: a `type: jwt` yaml entry with a non-empty vault refresh
// token produces a *events.RefreshableJWT keyed by route source.
func TestBuildCollectorCredentials_HappyJWTBootstrap(t *testing.T) {
	cfgCreds := map[string]config.CollectorCredential{
		"team": {
			Type:       "jwt",
			Token:      "access-eyJ.abc",
			ExpiresAt:  1_778_500_000,
			RefreshURL: "http://192.168.0.113:3000/auth/refresh",
		},
	}
	vault := fakeRefreshTokenSource{token: "long-refresh-token"}

	out := buildCollectorCredentials(cfgCreds, vault)
	if len(out) != 1 {
		t.Fatalf("want 1 credential, got %d (%+v)", len(out), out)
	}
	cred, ok := out["team"]
	if !ok {
		t.Fatalf("team route missing from output")
	}
	jwt, ok := cred.(*events.RefreshableJWT)
	if !ok {
		t.Fatalf("team credential should be *RefreshableJWT, got %T", cred)
	}
	if jwt.AccessToken != "access-eyJ.abc" {
		t.Errorf("AccessToken=%q", jwt.AccessToken)
	}
	if jwt.RefreshToken != "long-refresh-token" {
		t.Errorf("RefreshToken=%q (should come from vault, not yaml)", jwt.RefreshToken)
	}
	if jwt.RefreshURL != "http://192.168.0.113:3000/auth/refresh" {
		t.Errorf("RefreshURL=%q", jwt.RefreshURL)
	}
	want := time.Unix(1_778_500_000, 0)
	if !jwt.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt=%v, want %v", jwt.ExpiresAt, want)
	}
}

// Pre-login state: refresh_token is empty (no `aikey account login`
// has happened yet, or platform_account row missing). The credential
// MUST be skipped so reporter falls back to its legacy CollectorToken
// path — silently dropping events would be the wrong move when a user
// is still on the legacy service_token deployment shape.
func TestBuildCollectorCredentials_NoRefreshTokenSkipsRoute(t *testing.T) {
	cfgCreds := map[string]config.CollectorCredential{
		"team": {
			Type:       "jwt",
			Token:      "access",
			ExpiresAt:  9999,
			RefreshURL: "http://x:3000/auth/refresh",
		},
	}
	vault := fakeRefreshTokenSource{token: ""}

	out := buildCollectorCredentials(cfgCreds, vault)
	if out != nil {
		t.Fatalf("missing refresh_token must skip the route (returning nil), got %+v", out)
	}
}

// Vault error path: query failed for unrelated reasons (DB locked,
// transient SQLite error, etc.). Same skip-the-route behavior as the
// empty-token case — operational hint should be in the log; reporter
// keeps running on the legacy token path.
func TestBuildCollectorCredentials_VaultErrorSkipsRoute(t *testing.T) {
	cfgCreds := map[string]config.CollectorCredential{
		"team": {
			Type:       "jwt",
			Token:      "access",
			ExpiresAt:  9999,
			RefreshURL: "http://x:3000/auth/refresh",
		},
	}
	vault := fakeRefreshTokenSource{err: errors.New("simulated DB error")}

	out := buildCollectorCredentials(cfgCreds, vault)
	if out != nil {
		t.Fatalf("vault read error must skip the route (returning nil), got %+v", out)
	}
}

// Partial yaml bundle (e.g. token written but refresh_url missing): we
// can't construct a usable Bearer pipeline so the route is skipped —
// catches misconfigured deployments early instead of failing at the
// first upload attempt with an opaque "POST to '' failed".
func TestBuildCollectorCredentials_PartialYAMLBundleSkipsRoute(t *testing.T) {
	cases := []struct {
		name string
		cred config.CollectorCredential
	}{
		{"missing token", config.CollectorCredential{
			Type: "jwt", Token: "", ExpiresAt: 9999,
			RefreshURL: "http://x:3000/auth/refresh",
		}},
		{"missing refresh_url", config.CollectorCredential{
			Type: "jwt", Token: "access", ExpiresAt: 9999,
			RefreshURL: "",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := buildCollectorCredentials(
				map[string]config.CollectorCredential{"team": tc.cred},
				fakeRefreshTokenSource{token: "rt"},
			)
			if out != nil {
				t.Errorf("partial bundle should skip route, got %+v", out)
			}
		})
	}
}

// Unknown credential type: future-proofing — if yaml carries
// `type: mtls` or similar that this binary doesn't know how to handle,
// skip the route and log. NOT silently falling back to plaintext.
func TestBuildCollectorCredentials_UnknownTypeSkipsRoute(t *testing.T) {
	cfgCreds := map[string]config.CollectorCredential{
		"team": {
			Type:       "mtls", // future type proxy doesn't understand yet
			Token:      "access",
			ExpiresAt:  9999,
			RefreshURL: "http://x:3000/auth/refresh",
		},
	}
	out := buildCollectorCredentials(cfgCreds, fakeRefreshTokenSource{token: "rt"})
	if out != nil {
		t.Errorf("unknown type must skip the route, got %+v", out)
	}
}

// Empty yaml map: zero-cost happy default. Returning nil keeps the
// reporter on its legacy CollectorToken path — the back-compat
// guarantee we promised pre-B-phase deployments.
func TestBuildCollectorCredentials_EmptyConfigReturnsNil(t *testing.T) {
	out := buildCollectorCredentials(nil, fakeRefreshTokenSource{token: "rt"})
	if out != nil {
		t.Errorf("empty config must return nil, got %+v", out)
	}
}

// Mixed credentials: at least one route succeeds — return only the
// successful ones, don't poison the whole map. Models a future state
// where `personal` and `team` both have entries but the user is
// pre-login on the personal side.
func TestBuildCollectorCredentials_MixedSuccessAndSkip(t *testing.T) {
	cfgCreds := map[string]config.CollectorCredential{
		"team": {
			Type:       "jwt",
			Token:      "access-team",
			ExpiresAt:  9999,
			RefreshURL: "http://x:3000/auth/refresh",
		},
		"personal": {
			Type:       "unknown-type",
			Token:      "ignored",
			RefreshURL: "ignored",
		},
	}
	out := buildCollectorCredentials(cfgCreds, fakeRefreshTokenSource{token: "rt"})
	if len(out) != 1 {
		t.Fatalf("want 1 route wired (team), got %d: %+v", len(out), out)
	}
	if _, ok := out["team"]; !ok {
		t.Errorf("team route missing from output")
	}
	if _, ok := out["personal"]; ok {
		t.Errorf("personal route should have been skipped (unknown type)")
	}
}
