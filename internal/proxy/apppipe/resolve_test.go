package apppipe

// AKL-205 + Phase 2 Day 7 — Resolve tests.
//
// Split into two test groups matching the function split:
//
//   Resolve(...)               — metadata-only stage. Tests profile-id
//                                scope decision, R2 first-party re-check,
//                                app_records read errors / not found.
//
//   ResolveUpstreamBinding(...) — body-aware stage. Tests model-inferred
//                                upstream → binding lookup, the
//                                whitelist check against app.Upstreams,
//                                and the precise error codes for each
//                                failure path.
//
// We stub VaultReader with a fakeVault that returns whatever the test
// seeds — covers the same lookup shapes *vault.Reader produces without
// needing a real SQLite vault.

import (
	"errors"
	"net/http"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// fakeVault implements VaultReader. Fields ending in `Err` short-circuit
// the corresponding read with an error (covers the unhappy path); a nil
// return value covers "no row found".
type fakeVault struct {
	bindings   map[string]*vault.ProviderBinding // key = profileID + "|" + providerCode
	bindErr    error
	appRecord  *vault.AppRecord
	appRecErr  error
	aliasCreds map[string]*vault.AliasCredential // key = alias name; nil entry → "not found"
	aliasErr   error                              // when set, GetAliasCredential always errors
}

func (f *fakeVault) GetProviderBindingWithScope(profileID, providerCode string) (*vault.ProviderBinding, error) {
	if f.bindErr != nil {
		return nil, f.bindErr
	}
	return f.bindings[profileID+"|"+providerCode], nil
}

func (f *fakeVault) GetAppRecord(slug string) (*vault.AppRecord, error) {
	if f.appRecErr != nil {
		return nil, f.appRecErr
	}
	if f.appRecord == nil {
		return nil, nil
	}
	if f.appRecord.Slug != slug {
		return nil, nil
	}
	return f.appRecord, nil
}

func (f *fakeVault) GetAliasCredential(name string) (*vault.AliasCredential, error) {
	if f.aliasErr != nil {
		return nil, f.aliasErr
	}
	if f.aliasCreds == nil {
		return nil, nil
	}
	return f.aliasCreds[name], nil
}

func basicAppRoute(slug, kind string, followActive bool) *vkeys.ResolvedRoute {
	return &vkeys.ResolvedRoute{
		VirtualKeyID:     "app:" + slug,
		RouteSource:      "app",
		AppSlug:          slug,
		AppKind:          kind,
		AppKeyID:         "uuid-" + slug,
		FollowUserActive: followActive,
	}
}

// ─── Resolve() — metadata stage ─────────────────────────────────────────

func TestResolve_IsolatedThirdPartyHappy(t *testing.T) {
	fv := &fakeVault{
		appRecord: &vault.AppRecord{
			Slug:      "agent-a",
			Name:      "Agent A",
			Upstreams: []string{"openai"},
			AppKind:   "third-party",
		},
	}
	route := basicAppRoute("agent-a", "third-party", false)
	appCtx := &AppContext{Slug: "agent-a"}

	got, err := Resolve(fv, route, appCtx)
	if err != nil {
		t.Fatalf("expected success, got %+v", err)
	}
	if got.ProfileID != "app:agent-a" {
		t.Errorf("ProfileID = %q, want app:agent-a (isolated mode)", got.ProfileID)
	}
	if got.AppRecord.Name != "Agent A" {
		t.Errorf("AppRecord passthrough wrong: %+v", got.AppRecord)
	}
}

func TestResolve_FollowActiveFirstPartyUsesDefaultProfile(t *testing.T) {
	fv := &fakeVault{
		appRecord: &vault.AppRecord{
			Slug:      "degrade-detector",
			Upstreams: []string{"openai", "anthropic"},
			AppKind:   "first-party",
		},
	}
	route := basicAppRoute("degrade-detector", "first-party", true)
	appCtx := &AppContext{Slug: "degrade-detector"}

	got, err := Resolve(fv, route, appCtx)
	if err != nil {
		t.Fatalf("expected success, got %+v", err)
	}
	if got.ProfileID != "default" {
		t.Errorf("ProfileID = %q, want default (follow-active)", got.ProfileID)
	}
}

func TestResolve_FollowActiveOnThirdPartyRejected(t *testing.T) {
	// R2 mitigation — even if vault-tampering set follow_user_active=true
	// on a third-party slug, Resolve refuses to honor it.
	fv := &fakeVault{
		appRecord: &vault.AppRecord{
			Slug:      "evil-agent",
			Upstreams: []string{"openai"},
			AppKind:   "third-party",
		},
	}
	route := basicAppRoute("evil-agent", "third-party", true) // ← R2 attack scenario
	appCtx := &AppContext{Slug: "evil-agent"}

	_, err := Resolve(fv, route, appCtx)
	if err == nil {
		t.Fatalf("expected R2 reject, got success")
	}
	if err.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", err.StatusCode)
	}
	if err.ErrorCode != "FOLLOW_ACTIVE_NOT_ALLOWED" {
		t.Errorf("ErrorCode = %q, want FOLLOW_ACTIVE_NOT_ALLOWED", err.ErrorCode)
	}
}

func TestResolve_AppRecordMissingReturnsAppNotFound(t *testing.T) {
	fv := &fakeVault{appRecord: nil} // app row was deleted out from under proxy
	route := basicAppRoute("ghost-agent", "third-party", false)
	appCtx := &AppContext{Slug: "ghost-agent"}

	_, err := Resolve(fv, route, appCtx)
	if err == nil {
		t.Fatalf("expected APP_NOT_FOUND, got success")
	}
	if err.ErrorCode != "APP_NOT_FOUND" {
		t.Errorf("ErrorCode = %q, want APP_NOT_FOUND", err.ErrorCode)
	}
}

func TestResolve_AppRecordReadErrorBubblesUp(t *testing.T) {
	fv := &fakeVault{appRecErr: errors.New("disk read failure simulated")}
	route := basicAppRoute("any", "third-party", false)
	appCtx := &AppContext{Slug: "any"}

	_, err := Resolve(fv, route, appCtx)
	if err == nil {
		t.Fatalf("expected error, got success")
	}
	if err.ErrorCode != "APP_RECORD_READ_FAILED" {
		t.Errorf("ErrorCode = %q, want APP_RECORD_READ_FAILED", err.ErrorCode)
	}
}

func TestResolve_NilReaderReturnsServiceUnavailable(t *testing.T) {
	route := basicAppRoute("x", "third-party", false)
	appCtx := &AppContext{Slug: "x"}
	_, err := Resolve(nil, route, appCtx)
	if err == nil {
		t.Fatalf("expected error on nil reader, got success")
	}
	if err.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("StatusCode = %d, want 503", err.StatusCode)
	}
	if err.ErrorCode != "APP_VAULT_NOT_AVAILABLE" {
		t.Errorf("ErrorCode = %q, want APP_VAULT_NOT_AVAILABLE", err.ErrorCode)
	}
}

// ─── ResolveUpstreamBinding() — body-aware stage ────────────────────────

// resolvedFixture is a tiny helper that returns a ResolvedAppContext
// already populated as if Resolve() had succeeded for the slug.
func resolvedFixture(slug, kind string, upstreams []string) *ResolvedAppContext {
	return &ResolvedAppContext{
		ProfileID: "app:" + slug,
		AppRecord: &vault.AppRecord{
			Slug:      slug,
			Upstreams: upstreams,
			AppKind:   kind,
		},
		AppRoute: basicAppRoute(slug, kind, false),
	}
}

func TestResolveUpstreamBinding_HappyPath(t *testing.T) {
	fv := &fakeVault{
		bindings: map[string]*vault.ProviderBinding{
			"app:agent-a|anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal",
				KeySourceRef:  "my-anthropic-key",
			},
		},
	}
	r := resolvedFixture("agent-a", "third-party", []string{"anthropic"})
	binding, err := ResolveUpstreamBinding(fv, r, "anthropic")
	if err != nil {
		t.Fatalf("expected success, got %+v", err)
	}
	if binding.KeySourceRef != "my-anthropic-key" {
		t.Errorf("KeySourceRef = %q", binding.KeySourceRef)
	}
}

func TestResolveUpstreamBinding_EmptyInferred_Returns400(t *testing.T) {
	// Empty inferred upstream signals "couldn't recognize body.model".
	// We surface UPSTREAM_UNINFERRABLE so the client gets actionable info.
	r := resolvedFixture("agent-a", "third-party", []string{"openai"})
	_, err := ResolveUpstreamBinding(&fakeVault{}, r, "")
	if err == nil {
		t.Fatalf("expected UPSTREAM_UNINFERRABLE, got success")
	}
	if err.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want 400", err.StatusCode)
	}
	if err.ErrorCode != "UPSTREAM_UNINFERRABLE" {
		t.Errorf("ErrorCode = %q, want UPSTREAM_UNINFERRABLE", err.ErrorCode)
	}
}

func TestResolveUpstreamBinding_NotInAppManifest_Returns403(t *testing.T) {
	// App was registered with --upstreams openai only. body.model implied
	// anthropic — reject (vendor mid-flight scope expansion).
	r := resolvedFixture("openai-only-agent", "third-party", []string{"openai"})
	_, err := ResolveUpstreamBinding(&fakeVault{}, r, "anthropic")
	if err == nil {
		t.Fatalf("expected UPSTREAM_NOT_DECLARED, got success")
	}
	if err.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", err.StatusCode)
	}
	if err.ErrorCode != "UPSTREAM_NOT_DECLARED" {
		t.Errorf("ErrorCode = %q, want UPSTREAM_NOT_DECLARED", err.ErrorCode)
	}
}

func TestResolveUpstreamBinding_BindingMissing_IsolatedHint(t *testing.T) {
	// Upstream is declared, but `aikey app route` was never run for it.
	fv := &fakeVault{} // no bindings seeded
	r := resolvedFixture("no-binding-agent", "third-party", []string{"openai"})
	_, err := ResolveUpstreamBinding(fv, r, "openai")
	if err == nil {
		t.Fatalf("expected BINDING_NOT_FOUND, got success")
	}
	if err.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want 404", err.StatusCode)
	}
	if err.ErrorCode != "BINDING_NOT_FOUND" {
		t.Errorf("ErrorCode = %q, want BINDING_NOT_FOUND", err.ErrorCode)
	}
	// Hint specific to the isolated profile path (suggests `aikey app route`).
	if !containsSubstr(err.Message, "aikey app route") {
		t.Errorf("isolated-mode hint missing from message: %q", err.Message)
	}
}

func TestResolveUpstreamBinding_BindingMissing_FollowActiveHint(t *testing.T) {
	// Follow-active uses `default` profile; the hint should reference
	// `aikey use`, not `aikey app route`.
	fv := &fakeVault{}
	r := &ResolvedAppContext{
		ProfileID: "default",
		AppRecord: &vault.AppRecord{
			Slug:      "follow-active-agent",
			Upstreams: []string{"anthropic"},
			AppKind:   "first-party",
		},
		AppRoute: basicAppRoute("follow-active-agent", "first-party", true),
	}
	_, err := ResolveUpstreamBinding(fv, r, "anthropic")
	if err == nil {
		t.Fatalf("expected BINDING_NOT_FOUND, got success")
	}
	if !containsSubstr(err.Message, "aikey use") {
		t.Errorf("follow-active hint missing from message: %q", err.Message)
	}
}

func TestResolveUpstreamBinding_ReadErrorBubblesUp(t *testing.T) {
	fv := &fakeVault{bindErr: errors.New("PRAGMA failure simulated")}
	r := resolvedFixture("any", "third-party", []string{"openai"})
	_, err := ResolveUpstreamBinding(fv, r, "openai")
	if err == nil {
		t.Fatalf("expected error, got success")
	}
	if err.ErrorCode != "BINDING_READ_FAILED" {
		t.Errorf("ErrorCode = %q, want BINDING_READ_FAILED", err.ErrorCode)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// B mode (init_from_user_active) tests — credential-mode-architecture
// SPEC §1.1.B / §3.3 / §6.1. ResolveUpstreamBinding must short-circuit the
// provider-binding lookup when AppRecord.BoundAlias is non-empty and use
// vault.GetAliasCredential instead, mapping its status / errors to App
// pipeline error codes.
// ─────────────────────────────────────────────────────────────────────────

// boundFixture builds a ResolvedAppContext for an app in B mode.
func boundFixture(slug, kind, boundAlias string, upstreams []string) *ResolvedAppContext {
	return &ResolvedAppContext{
		// ProfileID is irrelevant in B mode — the alias lookup bypasses
		// the profile-scoped binding table. Set to "app:<slug>" anyway
		// so any logging that surfaces it is consistent with mode A.
		ProfileID: "app:" + slug,
		AppRecord: &vault.AppRecord{
			Slug:       slug,
			Upstreams:  upstreams,
			AppKind:    kind,
			BoundAlias: boundAlias,
			BoundAt:    1_700_000_000,
		},
		AppRoute: basicAppRoute(slug, kind, false),
	}
}

func TestResolveUpstreamBinding_BMode_HappyPath(t *testing.T) {
	// B mode lookup MUST consult GetAliasCredential, NOT
	// GetProviderBindingWithScope. Seed bindings empty + alias hit.
	want := &vault.ProviderBinding{
		ProviderCode:  "anthropic",
		KeySourceType: "personal_oauth_account",
		KeySourceRef:  "acct-abc",
	}
	fv := &fakeVault{
		aliasCreds: map[string]*vault.AliasCredential{
			"user@host.com": {Binding: want, Status: "active", AliasKind: "oauth"},
		},
	}
	r := boundFixture("first-party-x", "first-party", "user@host.com", []string{"anthropic"})
	got, rerr := ResolveUpstreamBinding(fv, r, "anthropic")
	if rerr != nil {
		t.Fatalf("expected success, got %+v", rerr)
	}
	if got != want {
		t.Errorf("expected synthetic binding from alias lookup; got different pointer (mode A path may have been taken)")
	}
}

func TestResolveUpstreamBinding_BMode_AliasMissing_Returns404(t *testing.T) {
	fv := &fakeVault{aliasCreds: map[string]*vault.AliasCredential{}}
	r := boundFixture("first-party-x", "first-party", "gone@host.com", []string{"anthropic"})
	_, rerr := ResolveUpstreamBinding(fv, r, "anthropic")
	if rerr == nil {
		t.Fatalf("expected BOUND_ALIAS_NOT_FOUND, got success")
	}
	if rerr.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want 404", rerr.StatusCode)
	}
	if rerr.ErrorCode != "BOUND_ALIAS_NOT_FOUND" {
		t.Errorf("ErrorCode = %q, want BOUND_ALIAS_NOT_FOUND", rerr.ErrorCode)
	}
}

func TestResolveUpstreamBinding_BMode_AliasRevoked_Returns403(t *testing.T) {
	fv := &fakeVault{
		aliasCreds: map[string]*vault.AliasCredential{
			"u@h.com": {
				Binding:   &vault.ProviderBinding{ProviderCode: "anthropic", KeySourceType: "personal_oauth_account", KeySourceRef: "acct-x"},
				Status:    "revoked",
				AliasKind: "oauth",
			},
		},
	}
	r := boundFixture("first-party-x", "first-party", "u@h.com", []string{"anthropic"})
	_, rerr := ResolveUpstreamBinding(fv, r, "anthropic")
	if rerr == nil {
		t.Fatalf("expected BOUND_ALIAS_REVOKED, got success")
	}
	if rerr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", rerr.StatusCode)
	}
	if rerr.ErrorCode != "BOUND_ALIAS_REVOKED" {
		t.Errorf("ErrorCode = %q, want BOUND_ALIAS_REVOKED", rerr.ErrorCode)
	}
}

func TestResolveUpstreamBinding_BMode_VaultError_Returns500(t *testing.T) {
	fv := &fakeVault{aliasErr: errors.New("alias DB read simulated")}
	r := boundFixture("first-party-x", "first-party", "anything", []string{"anthropic"})
	_, rerr := ResolveUpstreamBinding(fv, r, "anthropic")
	if rerr == nil {
		t.Fatalf("expected BOUND_ALIAS_READ_FAILED, got success")
	}
	if rerr.ErrorCode != "BOUND_ALIAS_READ_FAILED" {
		t.Errorf("ErrorCode = %q, want BOUND_ALIAS_READ_FAILED", rerr.ErrorCode)
	}
}

func TestResolveUpstreamBinding_BMode_UpstreamWhitelistStillApplies(t *testing.T) {
	// Even in B mode, the app's declared upstreams[] list governs scope.
	// A first-party app bound to oauth(anthropic) cannot suddenly send
	// openai traffic without re-registering — the UPSTREAM_NOT_DECLARED
	// check fires BEFORE the bound_alias short-circuit.
	fv := &fakeVault{
		aliasCreds: map[string]*vault.AliasCredential{
			"u@h.com": {
				Binding: &vault.ProviderBinding{ProviderCode: "anthropic", KeySourceType: "personal_oauth_account", KeySourceRef: "acct-x"},
				Status:  "active",
			},
		},
	}
	r := boundFixture("first-party-x", "first-party", "u@h.com", []string{"anthropic"})
	_, rerr := ResolveUpstreamBinding(fv, r, "openai") // not in Upstreams
	if rerr == nil {
		t.Fatalf("expected UPSTREAM_NOT_DECLARED, got success")
	}
	if rerr.ErrorCode != "UPSTREAM_NOT_DECLARED" {
		t.Errorf("ErrorCode = %q, want UPSTREAM_NOT_DECLARED — B mode does not bypass upstream-whitelist gate", rerr.ErrorCode)
	}
}

// containsSubstr is a tiny strings.Contains alternative that doesn't
// need an import (kept local to match resolve.go's flat-import style).
// Named *Substr to avoid collision with apppipe's existing containsString
// (which compares against a slice).
func containsSubstr(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
