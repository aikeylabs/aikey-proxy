// Package filterpipe is the protocol-contract placeholder for SPEC §1.5
// E mode (sync_filter). Real implementation lands in P4 once a concrete
// filter app (compliance detection, DLP, etc.) is in scope.
//
// What ships in P3 (this file):
//
//   - The reason_code enum below — locked at the wire-format level so
//     future filter apps + future proxy filter dispatcher implementations
//     can agree on the same vocabulary without renegotiating.
//
// What does NOT ship in P3:
//
//   - Unix domain socket / named pipe filter chain dispatch
//   - The msgpack v=1 request/response framing
//   - Performance budget enforcement (15ms p99 / 30ms p99 / etc.)
//
// Why ship the enum now: SPEC §1.5.7 mandates that the protocol contract
// is frozen ahead of implementation, so when P4 finally writes the
// dispatcher, callers (compliance app etc.) can already wire against
// these codes without churn. Pre-GA bookmark.
package filterpipe

// ReasonCode is the structured rejection / modification code a filter
// returns when its verdict is "block" or "modify" (SPEC §1.5.3 wire
// format). Free-form Message accompanies it; the code is what callers
// switch on for telemetry / routing.
//
// All codes use UPPER_SNAKE_CASE per the logging-conventions principle.
// Adding a new code is a coordinated change:
//
//  1. Add a new constant here
//  2. Update SPEC §1.5.3 reason_code list
//  3. Notify any active filter apps so they can emit the new code
//
// Removing a code is breaking — versioning lives at the wire-format v
// field (SPEC §1.5.3 currently v=1).
type ReasonCode string

// Reason codes a filter MAY return. Catalog ships small and grows on
// demand; subscribers MUST NOT reject unknown codes (forward compat).
const (
	// ReasonPIIDetected — the filter found personally identifiable
	// information in the request body (email, phone, government ID, etc.).
	ReasonPIIDetected ReasonCode = "PII_DETECTED"

	// ReasonSecretKeyLeak — the filter found an API key / token / cert
	// matching a known credential format leaking into the request body.
	ReasonSecretKeyLeak ReasonCode = "SECRET_KEY_LEAK"

	// ReasonPolicyViolation — the filter's content policy flagged this
	// request as disallowed. Catch-all for org-specific rules.
	ReasonPolicyViolation ReasonCode = "POLICY_VIOLATION"

	// ReasonFilterTimeout — used by the proxy itself (not the filter)
	// when filter_timeout_policy='fail_closed' and the filter exceeded
	// its deadline_ms allocation (SPEC §1.5.5 + §1.5.6).
	ReasonFilterTimeout ReasonCode = "FILTER_TIMEOUT"
)

// ProxyErrorCode_FilterNotImplemented is the HTTP body error code the
// proxy emits when a vault row declares filter_stages but no filterpipe
// implementation is loaded (i.e. the current P3 stub state, SPEC §1.5.7).
// Returning 501 with this code is the displayfn of the "fail-loud rather
// than silent-allow" invariant from SPEC §6.6 anti-example F.
const ProxyErrorCode_FilterNotImplemented = "FILTER_NOT_IMPLEMENTED"
