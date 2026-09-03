//go:build aikey_license_off

package supervisor

// licenseRails returns nothing in a LICENSING-OFF build: there is no gate to
// carry, so there is nothing for the rail to fetch.
//
// # Why the rail is skipped and not merely ignored
//
// license_gate_off.go already makes the forwarding decision unconditionally
// allow, so a running rail could not change any behavior. It could only produce
// noise — and it did: on a licensing-off cluster the control service serves no
// /v1/license/*, so the rail polled into a permanent 404 and the control plane
// logged `level=WARN http request rejected` several times a minute, forever.
// A steady stream of WARNs that everyone learns to ignore is how a real warning
// gets missed later.
//
// # 🚫 Why this does NOT weaken the rail's own invariant
//
// license_plane_rail.go says the rail "may not opt out of" railset's
// OK→STALE→OFFLINE visibility, because a licensing rail that starved silently
// would restore the very defect it was written for. That invariant is about a
// rail that EXISTS and stops working. Here the rail does not exist: the gate it
// feeds is compiled out, the marker that advertises the gate is absent from the
// binary, and the process refuses to start unless an operator acknowledged all
// of that (internal/licenseoff). The absence is declared in three places a
// release gate reads, so it cannot be mistaken for a rail that quietly died.
//
// The rail's code is deliberately left compiled — only its registration is
// dropped — so this build stays as close to the normal one as possible.
func (s *Supervisor) licenseRails() []railSpec { return nil }
