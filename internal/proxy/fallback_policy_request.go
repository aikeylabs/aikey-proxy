package proxy

// fallback_policy_request.go — carrying ONE threshold snapshot through ONE request
// (openspec change `aliyun-aigw-p0-upstream-fallback`, task 1b.6).
//
// # 🔴 Why the snapshot is taken at the entry and never again
//
// Task 1b.6: 「一次请求取一次快照，整条链共用」. The failure it prevents is not a
// rounding error, it is an UNREPRODUCIBLE one. The policy rail refreshes every 10
// seconds; if each hop of a chain re-read the cache, a poll landing mid-request
// would produce "hops 1–2 waited 120s, hop 3 waited 5s". The inputs are identical
// on the next run, the behavior is not, and nothing in the logs explains the
// difference — so whoever investigates concludes the timeout is flaky rather than
// that they are reading it twice.
//
// The mechanism is deliberately boring: `SnapshotForRequest` is called ONCE, in
// the supervisor's data-plane handler, and the result rides the request context.
// Every later reader takes it from the context. A source fence
// (fallback_policy_request_fence_test.go) asserts there is exactly one caller, so
// a per-hop re-read cannot be introduced quietly — it turns the fence red.
//
// # 🔴 Absence resolves to builtin, never to zero
//
// `FromContext` on a request that never passed the entry (a unit test, an internal
// probe constructed by hand) returns the BUILTIN defaults, not a zero Effective.
// That is I22 at the last mile: a zero-valued struct here would mean "0 ms budget,
// 0 ms cooldown", which is the exact instant-failure shape the three-state rule
// exists to prevent — and it would arrive silently, since a zero struct is what Go
// hands you for free.

import (
	"context"

	"github.com/AiKeyLabs/pkg/fallbackpolicy"
)

// fallbackPolicyCtxKey is unexported so no other package can plant or overwrite a
// snapshot; the entry point is the only writer.
type fallbackPolicyCtxKey struct{}

// WithFallbackPolicy attaches the request's single threshold snapshot.
//
// 🔴 Called ONLY from the data-plane entry (see the fence). Calling it deeper would
// re-scope the thresholds mid-request, which is the same defect as re-snapshotting.
func WithFallbackPolicy(ctx context.Context, eff fallbackpolicy.Effective) context.Context {
	return context.WithValue(ctx, fallbackPolicyCtxKey{}, eff)
}

// FallbackPolicyFromContext returns the snapshot governing this request.
//
// The second result reports whether a snapshot was actually attached. Callers that
// only need the numbers can ignore it — the first result is always usable, because
// the miss path returns builtin defaults rather than a zero value. The flag exists
// for diagnostics that must distinguish "the entry ran" from "we are looking at a
// synthetic request", which is a real difference when explaining a support case.
func FallbackPolicyFromContext(ctx context.Context) (fallbackpolicy.Effective, bool) {
	if eff, ok := ctx.Value(fallbackPolicyCtxKey{}).(fallbackpolicy.Effective); ok {
		return eff, true
	}
	return fallbackpolicy.Resolve(nil, fallbackpolicy.LocalOverrides{}), false
}

// SnapshotForRequest resolves the thresholds once for one request.
//
// 🔴 The name is load-bearing. `Snapshot` is the general accessor (health endpoint,
// rail logging, tests); this one means "and this is the ONLY time it happens for
// this request", which is what the fence keys on. Renaming it or adding a second
// caller is exactly the change that must not pass review unnoticed.
//
// A nil receiver answers with builtin defaults instead of panicking: a build where
// the capability is not wired still serves traffic, it just has nothing configured
// to apply.
func (c *FallbackPolicyCache) SnapshotForRequest() fallbackpolicy.Effective {
	if c == nil {
		return fallbackpolicy.Resolve(nil, fallbackpolicy.LocalOverrides{})
	}
	return c.Snapshot()
}
