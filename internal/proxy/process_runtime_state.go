package proxy

// OAuthPoolRuntimeState owns OAuth-pool facts whose lifetime is the Worker
// process, not one hot-reload generation. A draining generation can learn a
// cooldown, hard-revoked token, or newer Provider reset after its replacement
// is already active; both generations must therefore read and write the same
// stores and signal outbox.
//
// The fields stay private so generation-specific objects cannot replace one
// half of the state independently and recreate split ownership.
type OAuthPoolRuntimeState struct {
	poolCooldown       *poolCooldownStore
	poolObservedResets *poolResetStore
	signalReporter     *signalReporter
}

// NewOAuthPoolRuntimeState hydrates the process-wide OAuth-pool recovery state
// exactly once. Signal reporting starts dormant and is configured when the
// first fully-built generation is activated.
func NewOAuthPoolRuntimeState() *OAuthPoolRuntimeState {
	return &OAuthPoolRuntimeState{
		poolCooldown:       newPoolCooldownStore(),
		poolObservedResets: newPoolResetStore(),
		signalReporter:     newDormantSignalReporter(nil),
	}
}

// Shutdown retires process-owned background work. Hot-reload generation
// teardown must not call this; only Supervisor shutdown owns this lifecycle
// boundary. It is intentionally not named Close: the conservative PLANE-01
// graph follows every Close method reachable from response-body cleanup and
// would otherwise conflate this process-exit path with request forwarding.
func (s *OAuthPoolRuntimeState) Shutdown() error {
	if s == nil {
		return nil
	}
	// Drain the hard-revoke journal first. Cooldown snapshots are explicitly an
	// enhancement, while an accepted auth-failure is the only event that can
	// move Master out of a stale logged_in state. A wedged cooldown filesystem
	// write must not consume the Supervisor watchdog before that journal drains.
	var reporterErr error
	if s.signalReporter != nil {
		reporterErr = s.signalReporter.Close()
	}
	if s.poolCooldown != nil {
		s.poolCooldown.closePersistence()
	}
	return reporterErr
}
