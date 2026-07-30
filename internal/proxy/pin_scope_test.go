package proxy

// pin_scope_test.go — task 0b.8c of openspec change
// `aliyun-aigw-p0-upstream-fallback`, plus P6.2's rev8.2 injection.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDerivePinScopeThreeStates(t *testing.T) {
	for _, tc := range []struct {
		name, group, provider string
		want                  PinScope
		why                   string
	}{
		{
			name: "legacy row: no group id at all", group: "", provider: "",
			want: PinScopeLegacy,
			why: "a row written before route groups existed must keep its exact previous behavior; " +
				"the legacy case is keyed on the GROUP id, not the provider code, because " +
				"binding_provider_code is already NOT NULL DEFAULT '' and empty is a legal old value",
		},
		{
			name: "legacy row that happens to name a provider", group: "", provider: "anthropic",
			want: PinScopeLegacy,
			why:  "still no group → still the old path, regardless of the provider column",
		},
		{
			name: "group pin (the default)", group: "rg-main", provider: "",
			want: PinScopeGroup,
			why:  "pinning a chain keeps failover working, which is what a user almost always wants",
		},
		{
			name: "member pin", group: "rg-main", provider: "zhipu",
			want: PinScopeMember,
			why:  "one hop pinned; the group's provider uniqueness makes the code sufficient to locate it",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DerivePinScope(tc.group, tc.provider); got != tc.want {
				t.Errorf("DerivePinScope(%q,%q) = %v, want %v\n  why: %s",
					tc.group, tc.provider, got, tc.want, tc.why)
			}
		})
	}
}

// 🔴 The one case that silently removes a capability the user believes they have.
func TestOnlyMemberPinLosesFailover(t *testing.T) {
	if !PinScopeGroup.HasFailover() {
		t.Error("pinning the GROUP must keep failover — that is the default and the reason it is the default")
	}
	if !PinScopeLegacy.HasFailover() {
		t.Error("a legacy row's behavior must not change on upgrade")
	}
	if PinScopeMember.HasFailover() {
		t.Error("pinning ONE HOP means only that hop is used, so there is no failover. D-1③ chose " +
			"this over 'move it to the front' because a local action must not rewrite the order an " +
			"admin configured in the control plane (that would break I8 and R6/I7 at once) — and " +
			"the CLI is required to say so out loud when it happens")
	}
}

// 🔴 0b.8c: a pin to a hop that has since left the group falls back to a GROUP pin
// AND tells the user. Both alternatives are bugs.
func TestPinnedMemberRemovedFromGroupFallsBackToGroupPinAndNotifies(t *testing.T) {
	members := []string{"anthropic", "zhipu"}

	// Still present → unchanged, no notification noise.
	if scope, notify := PinnedMemberStillPresent("rg-main", "zhipu", members); scope != PinScopeMember || notify {
		t.Errorf("present member: got (%v, notify=%v), want (member, false)", scope, notify)
	}

	// Removed → fall back to the group and notify.
	scope, notify := PinnedMemberStillPresent("rg-main", "selfhost-gw", members)
	if scope != PinScopeGroup {
		t.Errorf("removed member: scope = %v, want group.\nThe two wrong answers are: pin nothing "+
			"(the pin evaporates while the user still believes traffic is fixed to one vendor), or "+
			"keep pinning a hop that no longer exists (requests fail against an upstream the admin "+
			"already removed, and the error points nowhere useful).", scope)
	}
	if !notify {
		t.Error("falling back silently is the failure mode 0b.8c forbids — the user chose one vendor " +
			"and is now getting a chain; they have to be told")
	}

	// Case-insensitive: provider codes are canonicalized elsewhere, so a case
	// difference must not look like a removed member.
	if scope, notify := PinnedMemberStillPresent("rg-main", "ZhiPu", members); scope != PinScopeMember || notify {
		t.Errorf("case-different member: got (%v, notify=%v), want (member, false)", scope, notify)
	}

	// A group pin is unaffected by membership changes.
	if scope, notify := PinnedMemberStillPresent("rg-main", "", members); scope != PinScopeGroup || notify {
		t.Errorf("group pin: got (%v, notify=%v), want (group, false)", scope, notify)
	}
}

// TestNoPinScopeColumnAnywhere — P6.2's rev8.2 injection, as a test:
// "注入「给钉选表加回 `pin_scope` 列」→「范围只推导不另存」的断言必须红".
//
// Two independently writable fields can contradict each other: `pin_scope=group`
// while also naming one provider has no legal meaning, and nothing would stop it
// being written. Same reasoning as I19's refusal of an editable `fallback_role` —
// make the invalid state unrepresentable rather than documenting which field wins.
func TestNoPinScopeColumnAnywhere(t *testing.T) {
	// Scan this repo's Go sources plus the CLI's migration file, which is where a
	// well-meaning future change would actually add the column.
	targets := []string{"."}
	if cli, err := filepath.Abs("../../../aikey-cli/src/migrations.rs"); err == nil {
		if _, statErr := os.Stat(cli); statErr == nil {
			targets = append(targets, cli)
		} else {
			t.Logf("aikey-cli migrations.rs not present at %s; scanning Go sources only", cli)
		}
	}

	var hits []string
	for _, root := range targets {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			ext := filepath.Ext(path)
			if ext != ".go" && ext != ".rs" {
				return nil
			}
			// This file necessarily names the column in order to forbid it.
			if strings.HasSuffix(path, "pin_scope_test.go") || strings.HasSuffix(path, "pin_scope.go") {
				return nil
			}
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			// 🔴 Match the column being DECLARED, not merely named.
			//
			// Two earlier drafts of this fence were too broad and flagged, in
			// turn, the migration file's comment explaining why there is no such
			// column, and a Rust test asserting its ABSENCE. Both are exactly the
			// kind of writing this change wants to encourage, so a fence that
			// punishes them is worse than useless — it teaches people to stop
			// documenting the decision.
			//
			// The hazard is narrow and concrete: a DDL statement that CREATES the
			// column. Match only that shape.
			for _, line := range strings.Split(string(b), "\n") {
				code := strings.TrimSpace(line)
				if !strings.Contains(code, "pin_scope") {
					continue
				}
				declaresColumn := strings.Contains(code, "ADD COLUMN pin_scope") ||
					strings.Contains(code, "pin_scope TEXT") ||
					strings.Contains(code, "pin_scope INTEGER") ||
					strings.Contains(code, "pin_scope VARCHAR")
				if declaresColumn {
					hits = append(hits, path+": "+code)
					break
				}
			}
			return nil
		})
	}

	if len(hits) > 0 {
		t.Errorf("`pin_scope` appears in %v.\nrev8.2 removed it deliberately: scope is DERIVED from "+
			"(route_group_id, binding_provider_code). Storing it alongside those two lets a row say "+
			"`pin_scope=group` while naming a single provider — a state with no legal meaning that "+
			"nothing prevents. Deriving costs one branch; storing costs a class of corrupt rows "+
			"forever.", hits)
	}
}
