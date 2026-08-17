package vkeys

// Property-based fence for PickRoutedAccount (2026-08-15, owner-approved item
// "1": business-invariant properties over example-based tests).
//
// WHY properties: the example fences in routed_pick_test.go pin specific
// scenarios; these properties pin the RULES themselves (R27 2026-08-15 修订 +
// R22.1) across thousands of randomized candidate/material/skip/override
// combinations, so a future edit that happens to satisfy the examples but
// violates the rule (exactly how the 2026-07-01 owner rule survived until
// schedstress P04) turns red here.
//
// Deliberately no third-party property library (rapid is MPL and shrinking is
// not worth a new supply-chain entry for one pure function): plain math/rand
// with FIXED seeds — failures print the seed + full case JSON, and re-running
// the same seed reproduces the exact sequence.
//
// The oracle predicates below are translated from the SPEC
// (workflow/CI/requirements/2026-06-23-oauth-account-pool.md R27/R22.1), not
// from the implementation — that is what makes them a fence rather than a
// mirror.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
)

type pickPropCase struct {
	SeatID   string                        `json:"seat_id"`
	Refs     []GroupAccountRef             `json:"refs"`
	Material map[string]GroupRuntimeAccount `json:"material"`
	Override string                        `json:"override"`
	Skip     map[string]bool               `json:"skip"`
	NowUnix  int64                         `json:"now_unix"`
}

func genPickPropCase(r *rand.Rand) pickPropCase {
	now := int64(1_700_000_000)
	n := 1 + r.Intn(6)
	c := pickPropCase{
		SeatID:   fmt.Sprintf("seat-%d", r.Intn(1000)),
		Material: map[string]GroupRuntimeAccount{},
		Skip:     map[string]bool{},
		NowUnix:  now,
	}
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		ids[i] = fmt.Sprintf("acc-%d", i)
		c.Refs = append(c.Refs, GroupAccountRef{AccountID: ids[i], Priority: 1 + r.Intn(3)})
	}
	// Blind mode (empty material) is a real spec state (pre-poll display) —
	// generate it ~10% of the time; otherwise each account draws a random
	// material shape.
	if r.Intn(10) > 0 {
		for _, id := range ids {
			if r.Intn(8) == 0 {
				continue // material not delivered for this account
			}
			mat := GroupRuntimeAccount{CredentialType: "oauth_account"}
			if r.Intn(10) == 0 {
				mat.CredentialType = "api_key" // no expiry/window/login axes
			} else {
				switch r.Intn(4) {
				case 0:
					mat.NeedsLogin = true
				case 1:
					mat.ExpiresAt = c.NowUnix - int64(r.Intn(1000)+1) // expired
				default:
					mat.ExpiresAt = c.NowUnix + 3600
				}
				if r.Intn(5) == 0 {
					mat.WindowStatus = "exhausted_current_window"
				}
				if r.Intn(7) == 0 {
					mat.Window7dStatus = "exhausted"
				}
			}
			c.Material[id] = mat
		}
	}
	for _, id := range ids {
		if r.Intn(5) == 0 {
			c.Skip[id] = true
		}
	}
	switch r.Intn(4) {
	case 0:
		c.Override = ids[r.Intn(n)]
	case 1:
		c.Override = "ghost-account" // non-candidate override must be ignored
	}
	return c
}

// Spec-level predicates (NOT copied from the gate implementation).
func (c pickPropCase) inSet(id string) bool {
	for _, ref := range c.Refs {
		if ref.AccountID == id {
			return true
		}
	}
	return false
}

// healthy: the account may SERVE right now. Blind mode (no material at all)
// degrades to rank/override-only per spec, so every non-skipped candidate
// counts as serviceable for display purposes.
func (c pickPropCase) healthy(id string) bool {
	if !c.inSet(id) || c.Skip[id] {
		return false
	}
	if len(c.Material) == 0 {
		return true
	}
	mat, ok := c.Material[id]
	if !ok || mat.NeedsLogin {
		return false
	}
	return MaterialUsable(mat, c.NowUnix)
}

// loginable: cannot serve, but a member login would fix it (the actionable
// prompt target class of the 2026-08-15 R27 revision).
func (c pickPropCase) loginable(id string) bool {
	if !c.inSet(id) || c.Skip[id] || len(c.Material) == 0 {
		return false
	}
	mat, ok := c.Material[id]
	return ok && mat.NeedsLogin
}

func (c pickPropCase) anyHealthy() bool {
	for _, ref := range c.Refs {
		if c.healthy(ref.AccountID) {
			return true
		}
	}
	return false
}

func (c pickPropCase) anyLoginable() bool {
	for _, ref := range c.Refs {
		if c.loginable(ref.AccountID) {
			return true
		}
	}
	return false
}

func TestPickRoutedAccount_Properties(t *testing.T) {
	const casesPerSeed = 4000
	for seed := int64(1); seed <= 6; seed++ {
		r := rand.New(rand.NewSource(seed))
		for i := 0; i < casesPerSeed; i++ {
			c := genPickPropCase(r)
			acc, oc := PickRoutedAccount(c.SeatID, c.Refs, c.Material, c.Override, c.Skip, c.NowUnix)
			fail := func(property, detail string) {
				raw, _ := json.Marshal(c)
				t.Fatalf("property %s violated (seed=%d case=%d): %s\n got=(%q,%v)\n case=%s",
					property, seed, i, detail, acc, oc, raw)
			}
			// P3 legality: any returned account is a non-skipped candidate.
			if acc != "" && (!c.inSet(acc) || c.Skip[acc]) {
				fail("P3-legality", "returned account outside the candidate set or skipped")
			}
			switch {
			case c.anyHealthy():
				// P1 (R27 2026-08-15): while ANY serviceable candidate exists the
				// member is NEVER blocked — no login prompt, no dead end.
				if oc != PickOK || !c.healthy(acc) {
					fail("P1-no-block", "healthy candidate exists but pick is not a healthy PickOK")
				}
				// P2: a serviceable engine override always wins.
				if c.healthy(c.Override) && acc != c.Override {
					fail("P2-override-priority", "healthy override was not chosen")
				}
			case c.anyLoginable():
				// P4: nothing serviceable + a login would fix it → actionable
				// prompt, preferring the engine's target.
				if oc != PickNeedsLogin || !c.loginable(acc) {
					fail("P4-actionable-prompt", "expected a loginable prompt target")
				}
				if c.loginable(c.Override) && acc != c.Override {
					fail("P4-override-prompt", "loginable override must own the prompt")
				}
			default:
				// P5: truly nothing to do.
				if oc != PickNone {
					fail("P5-dead-pool", "expected PickNone")
				}
			}
			// P6 purity: same inputs, same answer.
			acc2, oc2 := PickRoutedAccount(c.SeatID, c.Refs, c.Material, c.Override, c.Skip, c.NowUnix)
			if acc2 != acc || oc2 != oc {
				fail("P6-purity", fmt.Sprintf("second call diverged: (%q,%v)", acc2, oc2))
			}
		}
	}
}
