package supervisor

// managed_profile_parity_test.go — parity fence between the two copies of the
// (provider, protocol) → broker OAuth profile mapping that exist after tasks
// 1.1 of roadmap20260320/技术实现/阶段9-商业化版本/master-central-oauth-login:
//
//   - member side: poolProviderFor (group_login_handler.go), which the member
//     pool login keeps using unchanged this phase (R-master-central-login-10.S2);
//   - master side: broker.ManagedLoginProfile, exported by aikey-auth-broker for
//     the master-central browser OAuth login.
//
// Why a test instead of rewiring poolProviderFor onto the broker: the design
// deliberately leaves the member path untouched this phase, and this fence is
// what keeps the two copies from drifting (DEC-master-central-login-2 premise 5,
// design.md of that package). Guards R-master-central-login-2.S1: the profile
// master logs in with is the one the member logs in with, including the Mock
// authorize parameters the Resident Mock checks
// (aikey-mock-provider/internal/server/oauth.go:110-126).

import (
	"reflect"
	"sort"
	"testing"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
)

func TestManagedLoginProfileMatchesPoolProviderFor(t *testing.T) {
	const (
		mockRoot  = "https://mock.example.test"
		mockCtx   = "opaque-signed-context.signature"
		credID    = "cred-parity-1"
		loginHint = "pool-parity@example.test"
	)
	for _, tc := range []struct {
		name, provider, protocol string
		// mockPath is the protocol segment master puts in the Mock endpoints it
		// hands the member (aikey-control-master/service/internal/api/
		// routed_credential.go:195,197: <root>/oauth/<protocol>/{authorize,token}).
		// Empty for official providers, which get no Mock endpoints.
		mockPath string
	}{
		{name: "anthropic", provider: "anthropic", protocol: "anthropic"},
		{name: "openai", provider: "openai", protocol: "openai_compatible"},
		{name: "anthropic_empty_protocol_alias", provider: "anthropic", protocol: ""},
		{name: "openai_empty_protocol_alias", provider: "openai", protocol: ""},
		{name: "mock_anthropic", provider: "mock", protocol: "anthropic", mockPath: "anthropic"},
		{name: "mock_openai_compatible", provider: "mock", protocol: "openai_compatible", mockPath: "openai_compatible"},
		{name: "normalized_codes", provider: "  Anthropic ", protocol: "ANTHROPIC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Both sides get the same pair of per-login values: the member reads
			// them from the login context, master passes them explicitly.
			loginCtx := poolLoginContext{
				CredentialID:     credID,
				ProviderCode:     tc.provider,
				ProtocolType:     tc.protocol,
				ExpectedIdentity: loginHint,
			}
			if tc.mockPath != "" {
				loginCtx.OAuthAuthorizeURL = mockRoot + "/oauth/" + tc.mockPath + "/authorize"
				loginCtx.OAuthTokenURL = mockRoot + "/oauth/" + tc.mockPath + "/token"
				loginCtx.OAuthContext = mockCtx
			}
			member, ok := poolProviderFor(loginCtx)
			if !ok {
				t.Fatalf("poolProviderFor rejected supported input %q/%q", tc.provider, tc.protocol)
			}
			memberCfg := member.config
			if memberCfg == nil {
				// Official providers: the member starts by registry code
				// (brokerPoolExchanger.StartLogin → broker.StartLogin), so this
				// registry entry IS the profile it logs in with.
				memberCfg = broker.GetProviderConfig(member.broker)
				if memberCfg == nil {
					t.Fatalf("poolProviderFor named broker profile %q, which the registry does not have", member.broker)
				}
			}

			masterCfg, masterFlow, err := broker.ManagedLoginProfile(tc.provider, tc.protocol, mockRoot, mockCtx, credID, loginHint)
			if err != nil {
				t.Fatalf("ManagedLoginProfile(%q, %q): %v", tc.provider, tc.protocol, err)
			}
			if masterFlow != member.flow {
				t.Errorf("flow: master %q, member %q", masterFlow, member.flow)
			}
			if !reflect.DeepEqual(*masterCfg, *memberCfg) {
				t.Errorf("profile differs between master and member in fields %v", providerConfigDiffFields(*masterCfg, *memberCfg))
			}
		})
	}
}

// providerConfigDiffFields names the differing ProviderConfig fields (and
// ExtraAuthorizeParams keys). Names only: values can carry the signed Mock
// context.
func providerConfigDiffFields(a, b broker.ProviderConfig) []string {
	var diff []string
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	for i := 0; i < av.NumField(); i++ {
		name := av.Type().Field(i).Name
		if name == "ExtraAuthorizeParams" {
			keys := map[string]bool{}
			for k := range a.ExtraAuthorizeParams {
				keys[k] = true
			}
			for k := range b.ExtraAuthorizeParams {
				keys[k] = true
			}
			for k := range keys {
				av2, aok := a.ExtraAuthorizeParams[k]
				bv2, bok := b.ExtraAuthorizeParams[k]
				if aok != bok || av2 != bv2 {
					diff = append(diff, "ExtraAuthorizeParams["+k+"]")
				}
			}
			continue
		}
		if !reflect.DeepEqual(av.Field(i).Interface(), bv.Field(i).Interface()) {
			diff = append(diff, name)
		}
	}
	sort.Strings(diff)
	return diff
}
