package proxy

// chain_cooldown_identity_test.go — the fence for F-6 cooldown / F-7 stickiness
// having a hop identity at all (found on staging, 2026-07-31).
//
// 🔴 `ResolvedRoute.BindingID` is empty on every chain built from the local vault
// cache — its own comment says so, and nothing populates it. Cooldown and
// stickiness keyed on it directly, so `note("")` wrote one entry under the empty
// key and `cooling("")` then reported EVERY candidate as cooling. Banding them
// all the same leaves the original order intact, so the feature degraded to a
// no-op instead of failing: on staging a dead primary was re-dialled ~56s after
// failing, well inside the 5-minute builtin cooldown.
//
// 🚫 Asserting "cooldown works" with a populated BindingID would have passed
// throughout the bug. These tests deliberately leave BindingID EMPTY, because
// that is the only state the cluster and the CLI cache actually produce.

import (
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/fallbackpolicy"
)

// cooldownForTest is the builtin 5-minute default — the value that was already in
// force on staging and still did not deprioritise anything.
func cooldownForTest() fallbackpolicy.Resolved {
	return fallbackpolicy.Resolved{
		Value:  fallbackpolicy.DefaultBindingCooldownMs,
		Source: fallbackpolicy.SourceBuiltin,
	}
}

func TestHopKey_DistinguishesHopsWhenBindingIDIsAbsent(t *testing.T) {
	primary := &vkeys.ResolvedRoute{VirtualKeyID: "vk-1", CredentialID: "cred-a"}
	fallback := &vkeys.ResolvedRoute{VirtualKeyID: "vk-1", CredentialID: "cred-b"}

	if hopKey(primary) == "" || hopKey(fallback) == "" {
		t.Fatal("a hop built from the cache must still have an identity; an empty key is what " +
			"collapsed every candidate into one cooldown entry")
	}
	if hopKey(primary) == hopKey(fallback) {
		t.Fatalf("two hops of one chain must not share an identity: %q == %q — cooling the "+
			"primary would then also cool the fallback and the chain would have nowhere to go",
			hopKey(primary), hopKey(fallback))
	}

	// 🔴 Blast radius: the same credential under a DIFFERENT key is a different
	// hop. Keying on credential alone would pull this upstream out of another
	// person's chain because of a failure in this one.
	other := &vkeys.ResolvedRoute{VirtualKeyID: "vk-2", CredentialID: "cred-a"}
	if hopKey(other) == hopKey(primary) {
		t.Errorf("a cooldown must not cross virtual keys: vk-1 and vk-2 share credential "+
			"cred-a but are separate bindings (%q)", hopKey(primary))
	}

	// The real binding id wins when it is finally carried through.
	withID := &vkeys.ResolvedRoute{BindingID: "b-1", VirtualKeyID: "vk-1", CredentialID: "cred-a"}
	if hopKey(withID) != "b-1" {
		t.Errorf("hopKey must prefer the real binding id once present, got %q", hopKey(withID))
	}
}

// The end-to-end property: a hop that just failed must be DEPRIORITISED on the
// next request. This is what the operator sees — the dead primary stops being
// dialled first — and it is what silently did not happen.
func TestCooldown_DeprioritisesAFailedHopWithNoBindingID(t *testing.T) {
	store := newBindingCooldownStore()
	now := time.Now()

	primary := &vkeys.ResolvedRoute{VirtualKeyID: "vk-1", CredentialID: "cred-primary"}
	fallback := &vkeys.ResolvedRoute{VirtualKeyID: "vk-1", CredentialID: "cred-fallback"}
	candidates := []*vkeys.ResolvedRoute{primary, fallback}

	// The primary answers 500, exactly as the staging run did.
	if _, cooled := store.note(hopKey(primary), 500, nil, cooldownForTest(), now); !cooled {
		t.Fatal("a 5xx on a hop must start a cooldown; without one the chain re-dials a dead " +
			"upstream on every request")
	}
	if _, cooling := store.cooling(hopKey(primary), now.Add(time.Second)); !cooling {
		t.Fatal("the failed hop must read as cooling immediately after")
	}
	if _, cooling := store.cooling(hopKey(fallback), now.Add(time.Second)); cooling {
		t.Fatal("the healthy fallback must NOT be cooling — that was the collapse: one empty " +
			"key made every candidate look cooled at once")
	}

	ordered := orderCandidates(candidates, "", store, now.Add(time.Second))
	if len(ordered) != 2 {
		t.Fatalf("the chain must still be walked in full, got %d candidates", len(ordered))
	}
	if ordered[0] != fallback {
		t.Errorf("the cooled primary must not be tried first on the next request; got the " +
			"primary again, which is precisely the observed staging behaviour")
	}
}
