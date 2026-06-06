//go:build race

package apphook

// raceEnabled is true when the test binary is built with -race. Latency-SLO
// benchmarks skip in this mode: the race detector inflates every operation
// ~10×, so the measured numbers aren't the production latency and would fail the
// <1ms SLO spuriously. Correctness tests still run under -race.
const raceEnabled = true
