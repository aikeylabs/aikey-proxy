package proxy

// OAuthPoolRuntimeState owns OAuth-pool facts whose lifetime is the Worker
// process, not one hot-reload generation. A draining generation can learn a
// cooldown or hard-revoked token after its replacement is already active; both
// generations must therefore read and write the same store and signal outbox.
//
// The fields stay private so generation-specific objects cannot replace one
// half of the state independently and recreate split ownership.
type OAuthPoolRuntimeState struct {
	poolCooldown   *poolCooldownStore
	signalReporter *signalReporter
}

// NewOAuthPoolRuntimeState hydrates the process-wide OAuth-pool recovery state
// exactly once. Signal reporting starts dormant and is configured when the
// first fully-built generation is activated.
func NewOAuthPoolRuntimeState() *OAuthPoolRuntimeState {
	return &OAuthPoolRuntimeState{
		poolCooldown:   newPoolCooldownStore(),
		signalReporter: newDormantSignalReporter(nil),
	}
}

// Close retires process-owned background work. Hot-reload generation teardown
// must not call this; only Supervisor shutdown owns this lifecycle boundary.
func (s *OAuthPoolRuntimeState) Close() error {
	if s == nil || s.signalReporter == nil {
		return nil
	}
	return s.signalReporter.Close()
}
