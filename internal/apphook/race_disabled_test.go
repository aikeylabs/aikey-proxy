//go:build !race

package apphook

// raceEnabled is false in normal (non-race) test builds. See race_enabled_test.go.
const raceEnabled = false
