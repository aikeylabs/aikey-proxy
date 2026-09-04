// Package licenseoff holds the boot interlock for a LICENSING-OFF proxy build.
//
// 🔴 Why this is a package of its own rather than a file in internal/proxy.
// This module asserts, in TestThisModuleDoesNotDependOnLicensingAtAll and in the
// hot-path call-graph fence, that the forwarding path knows ONE WORD and not a
// license state machine. The interlock is not part of that path and must not
// look like it is: it decides whether this BINARY may run at all, before any
// request is served, in a build that has no gate to consult.
//
// It is also the one place in this module allowed to read the environment for a
// licensing-adjacent reason. That is acceptable only because nothing it returns
// influences a forwarding decision — it either lets the process start or stops
// it. 🚫 Do not put gate logic here to escape a fence.
//
// The contract is deliberately IDENTICAL to the control service's
// internal/licenseoff: same variable name, same refusal, same "announce on every
// boot" behavior. An operator who has met one has met both, and cluster-install
// writes one variable for the whole host rather than one per component.
package licenseoff
