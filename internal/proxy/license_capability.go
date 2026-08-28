package proxy

// license_capability.go — the marker this binary carries so a release pipeline
// can read back, out of the built file, whether this proxy consumes the licence
// forwarding gate.
//
// # The failure this exists to catch
//
// Until 2026-08-27 this repository had a gate-shaped hole: the control plane
// computed a forwarding verdict and served it, and nothing here read it, so an
// expired deployment forwarded for ever. The gate is wired now — and the way it
// would silently come UNWIRED again is a release cut from a branch that predates
// it. Nothing about such a build looks wrong: it starts, it serves, it simply
// never refuses. That is the same "absent is indistinguishable from satisfied"
// shape as the original defect.
//
// So the release gate asserts the capability is present in the artifact rather
// than trusting the branch.
// See workflow/CI/bugfix/20260827-forwarding-gate-was-never-wired.md.
//
// # 🚫 Why the marker is declared HERE and not imported
//
// aikey-proxy deliberately does not depend on aikey-license-core AT ALL —
// hotpath_callgraph_fence_test.go asserts it for the request path and
// TestThisModuleDoesNotDependOnLicensingAtAll asserts it for the whole module.
// Importing a shared constant to satisfy a release check would break the very
// property the forwarding gate was designed around: the data path knows one
// word, not a licence state machine. Two short literals in two repositories is
// the correct cost.

// The licence-consumer capabilities a proxy built from THIS source has.
const (
	// CapPlaneRail: this proxy polls the control plane for the forwarding gate
	// and refuses requests while it says deny. Its absence is the whole defect.
	CapPlaneRail = "plane-rail"
	// CapPlaneCeiling: this proxy stops honouring a gate value it can no longer
	// refresh (LicensePlaneStaleCeiling). Declared separately from the rail
	// because a build could plausibly have one without the other, and a rail
	// without a ceiling is bypassed by unplugging the control plane.
	CapPlaneCeiling = "plane-ceiling"
)

// SupportedLicenseCapabilities is what this build does.
//
// Adding one means adding it here AND to LicenseConsumerMarker below;
// TestTheLicenseConsumerMarkerMatchesWhatIsSupported keeps the two in step so the
// marker cannot become aspirational.
var SupportedLicenseCapabilities = []string{CapPlaneRail, CapPlaneCeiling}

// LicenseConsumerMarkerPrefix is the fixed, greppable prefix.
const LicenseConsumerMarkerPrefix = "aikey-license/consumer:"

// LicenseConsumerMarkerTerminator ends the list.
//
// 🔴 LOAD-BEARING. The equivalent marker in aikey-license-core came out of a
// cross-compiled linker as `aikeylic/capabilities:bearer-authnumber`, with an
// unrelated literal packed flush against it; a reader that ended the list at the
// first non-letter read a capability that matched nothing and would have refused
// a binary built from that very source. ';' is not legal in a capability name,
// so nothing the linker places next can be mistaken for part of the list.
const LicenseConsumerMarkerTerminator = ";"

// LicenseConsumerMarker is the exact string this binary carries.
//
// 🔴 ONE CONTIGUOUS LITERAL, NOT BUILT AT RUN TIME. The first version of this
// pattern elsewhere joined its list with strings.Join, and `strings` on the
// resulting binary found only the prefix — the linker had no reason to place the
// pieces near each other. The reader then saw an empty list and would have
// refused a current binary, the failure direction that mimics the bug being
// guarded against. 🚫 Do not "tidy" this into a Join or a fmt.Sprintf.
const LicenseConsumerMarker = LicenseConsumerMarkerPrefix +
	"plane-rail,plane-ceiling" +
	LicenseConsumerMarkerTerminator
