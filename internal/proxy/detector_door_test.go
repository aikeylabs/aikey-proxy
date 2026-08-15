package proxy

// detector_door_test.go — the ONE way a test in package `proxy` reaches the
// env-provided ai-compliance-detector binary. Everything that spawns the
// detector goes through liveDetectorBinary (env-provided binary, here) or
// detectortest.SiblingBinary (sibling-repo build, shared with
// internal/supervisor); both seal the host state before returning.
//
// ── Why a door and not a call at each site (2026-08-14) ─────────────────────
//
// Before this file, five live tests each read AIKEY_TEST_DETECTOR_BINARY
// themselves and nine integration tests each built the sibling path themselves.
// Exactly ONE of the fourteen (the NSFW one) sealed the host state, because
// sealing was discovered while debugging that one test. That is the shape the
// project calls out: a concept with no name gets re-derived by hand at every
// site, and the site that forgets is invisible.
//
// So the concept gets a name and one exit. detectortest.Seal carries the WHY
// (four $HOME-rooted detector inputs, only one of which has an env switch);
// detectortest.Sealed.AssertHeld is the anti-regression half — deleting the seal
// must turn a test RED rather than quietly hand it the developer's ~/.aikey.
//
// Fenced by internal/detectortest/seal_fence_test.go: the tokens that can yield
// a detector binary path (the env var name, the "bin/detector" path segments)
// are allowed in THIS file only, and this file must call detectortest.Seal.
//
// ── Why the sibling-repo path has NO local wrapper here (2026-08-14) ─────────
//
// The first cut of this file also carried an `integDetectorBinary` alias that
// only forwarded to detectortest.SiblingBinary. It bought nothing: the fence
// pins the sibling path by its LITERAL ("bin", "detector"), which lives in
// detectortest and nowhere else, so the seal rule already reaches every caller
// of SiblingBinary no matter which package it sits in — internal/supervisor's
// max-action harness has always called it directly for exactly that reason.
// The alias was also invisible to a default (untagged) build, since its only
// callers are `//go:build integration` files, so it read as dead code to the
// linter. One door per SOURCE, not one wrapper per package.

import (
	"os"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/detectortest"
)

// liveDetectorBinaryEnv points at a detector built by the caller
// (`make -f workflow/CI/Makefile p4-filter-live` builds it to
// /tmp/aikey-detector-p4). Unset ⇒ the live tests skip, so a bare `go test ./...`
// does not require the sibling repo.
const liveDetectorBinaryEnv = "AIKEY_TEST_DETECTOR_BINARY"

// liveDetectorBinary is the door for the env-gated live tests. It skips when no
// binary was provided, and otherwise returns a sealed host state alongside the
// path.
//
// The seal happens HERE, before the caller can spawn anything, so a new live
// test cannot be written in a way that spawns an unsealed child — the only way
// to learn the binary path is to call this.
func liveDetectorBinary(t *testing.T, what string) (string, detectortest.Sealed) {
	t.Helper()
	bin := os.Getenv(liveDetectorBinaryEnv)
	if bin == "" {
		t.Skipf("set %s to the built detector binary to run %s", liveDetectorBinaryEnv, what)
	}
	return bin, detectortest.Seal(t)
}
