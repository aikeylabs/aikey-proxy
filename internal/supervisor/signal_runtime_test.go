package supervisor

import "testing"

func TestRuntimeRefreshTokenSourceFollowsActivatedVault(t *testing.T) {
	firstPath, _ := newOpenableVault(t, nil)
	addPlatformAccount(t, firstPath, "refresh-token-first")
	secondPath, _ := newOpenableVault(t, nil)
	addPlatformAccount(t, secondPath, "refresh-token-second")

	source := newRuntimeRefreshTokenSource(firstPath, "pw")
	got, err := source.GetPlatformRefreshToken()
	if err != nil || got != "refresh-token-first" {
		t.Fatalf("first active vault token=(%q, %v), want refresh-token-first", got, err)
	}

	source.update(secondPath, "pw")
	got, err = source.GetPlatformRefreshToken()
	if err != nil || got != "refresh-token-second" {
		t.Fatalf("second active vault token=(%q, %v), want refresh-token-second", got, err)
	}
}
