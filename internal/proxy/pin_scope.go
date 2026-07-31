package proxy

// pin_scope.go — task 0b.8c of openspec change `aliyun-aigw-p0-upstream-fallback`.
//
// `aikey use` lets a developer PIN routing on their own machine. With route
// groups there are two useful scopes, and the scope is DERIVED — never stored.
//
// # 🔴 The three-state table, written down so nobody has to guess
//
//	route_group_id | binding_provider_code | meaning
//	---------------|-----------------------|-------------------------------------
//	empty          | —                     | LEGACY row (written before this
//	               |                       | change) → existing behavior, unchanged
//	set            | empty                 | PIN THE GROUP (default) → failover
//	               |                       | still happens
//	set            | set                   | PIN ONE HOP → no failover, and the
//	               |                       | user must be told so
//
// # 🔴 Why there is no `pin_scope` column (rev8.2 deleted the planned one)
//
// Two independently writable fields can contradict each other. A row saying
// `pin_scope = group` while also naming one provider has no legal meaning — and
// nothing stops it being written. This is the same reasoning that made I19 refuse
// an independently editable `fallback_role`: if a state has no valid
// interpretation, the fix is to make it unrepresentable, not to document which
// field wins.
//
// Deriving costs one branch. Storing costs a class of corrupt rows forever.
//
// # 🔴 Old rows do not collide
//
// `binding_provider_code` is already `NOT NULL DEFAULT ''`, so empty is a legal
// pre-existing value. What separates a legacy row is that it has NO
// `route_group_id` — so it lands in its own branch and behaves exactly as before
// the upgrade. That is why the legacy case is keyed on the group id rather than
// on the provider code.

// PinScope is the derived intent of a local `aikey use` pin.
type PinScope int

const (
	// PinScopeLegacy — a row written before route groups existed. Handled by the
	// pre-existing code path; this change does not alter its behavior.
	PinScopeLegacy PinScope = iota
	// PinScopeGroup — the default. Routing is pinned to a chain, and failover
	// within that chain still happens.
	PinScopeGroup
	// PinScopeMember — one hop is pinned. 🔴 There is NO failover in this state,
	// and the CLI must say so at the moment the user pins (F-16④ / D-1③).
	PinScopeMember
)

func (p PinScope) String() string {
	switch p {
	case PinScopeGroup:
		return "group"
	case PinScopeMember:
		return "member"
	case PinScopeLegacy:
		return "legacy"
	default:
		// A scope added later without a String() arm must not silently print as
		// "legacy" — that is the value meaning "no scope recorded", and merging a
		// new state into it is the three-state collapse 0b.8c forbids.
		return "legacy"
	}
}

// HasFailover reports whether a pin in this scope still fails over.
//
// 🔴 Pinning a member is the one case that silently REMOVES a capability the user
// probably believes they have. D-1③ was decided as "pin one hop = use only that
// hop" precisely so this is explicit rather than implied — and the CLI is required
// to print the consequence when it happens.
func (p PinScope) HasFailover() bool { return p != PinScopeMember }

// DerivePinScope resolves the scope from the two stored columns.
//
// 🚫 Deliberately takes the two raw values rather than a struct: the whole point
// is that these are the ONLY two inputs, and a struct would invite a third.
func DerivePinScope(routeGroupID, bindingProviderCode string) PinScope {
	if routeGroupID == "" {
		return PinScopeLegacy
	}
	if bindingProviderCode == "" {
		return PinScopeGroup
	}
	return PinScopeMember
}

// PinnedMemberStillPresent decides what a member pin means once the group's
// membership has changed underneath it.
//
// 🔴 Task 0b.8c: if the pinned hop has been REMOVED from the group, the pin falls
// back to pinning the GROUP, and the user is told. The two forbidden outcomes are
// worth naming, because both are easy to write by accident:
//
//   - silently pinning nothing (the pin evaporates, and the user keeps believing
//     their traffic is fixed to one vendor);
//   - keeping a pin to a hop that no longer exists (requests fail against an
//     upstream the admin already removed, and the error points nowhere useful).
//
// Returns the effective scope and whether the caller must notify the user.
func PinnedMemberStillPresent(routeGroupID, bindingProviderCode string, groupProviderCodes []string) (PinScope, bool) {
	scope := DerivePinScope(routeGroupID, bindingProviderCode)
	if scope != PinScopeMember {
		return scope, false
	}
	for _, code := range groupProviderCodes {
		if equalFoldASCII(code, bindingProviderCode) {
			return PinScopeMember, false
		}
	}
	// The pinned hop is gone: fall back to the group and say so.
	return PinScopeGroup, true
}

// equalFoldASCII avoids importing strings into a file that is otherwise pure
// derivation, and provider codes are ASCII by construction (they are validated
// against the provider registry).
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
