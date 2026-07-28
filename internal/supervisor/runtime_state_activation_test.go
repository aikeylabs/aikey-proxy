package supervisor

import (
	"context"
	"net/http"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// runtimeStateRecorder proves that every supervisor-owned runtime setting is
// installed through one activation path. A new setting added to Supervisor must
// join this contract or a reload can silently reactivate an older value.
type runtimeStateRecorder struct {
	transport http.RoundTripper
	override  bool
	broker    proxy.OAuthBroker
}

func (r *runtimeStateRecorder) SetTransport(transport http.RoundTripper) {
	r.transport = transport
}

func (r *runtimeStateRecorder) SetOAuthEgressOverride(enabled bool) {
	r.override = enabled
}

func (r *runtimeStateRecorder) SetBroker(broker proxy.OAuthBroker) {
	r.broker = broker
}

type runtimeStateRoundTripper struct{ id string }

func (*runtimeStateRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, nil
}

type runtimeStateBroker struct{ id string }

func (*runtimeStateBroker) EnsureFresh(context.Context, string) error { return nil }

func (*runtimeStateBroker) ResolveCredential(context.Context, string) (*proxy.OAuthCredential, error) {
	return nil, nil
}

func (*runtimeStateBroker) GetAccountStatus(context.Context, string) (string, error) {
	return "active", nil
}

func TestApplyRuntimeStateIncludesEveryReloadSensitiveSetting(t *testing.T) {
	s := &Supervisor{}
	wantTransport := &runtimeStateRoundTripper{id: "latest"}
	wantBroker := &runtimeStateBroker{id: "latest"}
	s.transport.Store(&transportBox{rt: wantTransport})
	s.oauthEgressOverride.Store(true)
	s.broker = wantBroker

	got := &runtimeStateRecorder{}
	s.applyRuntimeState(got)

	if got.transport != wantTransport {
		t.Fatalf("transport = %p, want latest %p", got.transport, wantTransport)
	}
	if !got.override {
		t.Fatal("oauth egress override was not applied to the activating generation")
	}
	if got.broker != wantBroker {
		t.Fatalf("broker = %p, want latest %p", got.broker, wantBroker)
	}
}

// Regression for the hot-update versus Reload activation race:
//
//  1. Reload finishes building a generation with an old runtime snapshot.
//  2. Settings hot-applies a new value to the currently active generation.
//  3. Reload activates its stale generation after the Settings request returned.
//
// Activation and hot updates must share one short critical section. Whichever
// operation wins first, the generation left active after both complete must hold
// the latest supervisor-owned value.
func TestActivateGenerationSerializesWithRuntimeHotUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := &Supervisor{}
	oldGen := &generation{proxy: proxy.New(nil, nil, nil, nil, ctx)}
	newGen := &generation{proxy: proxy.New(nil, nil, nil, nil, ctx)}
	s.active.Store(oldGen)

	// Hold the activation fence so both operations are definitely concurrent at
	// the boundary that used to lose the hot update.
	s.runtimeStateMu.Lock()
	activateDone := make(chan struct{})
	go func() {
		s.activateGeneration(newGen)
		close(activateDone)
	}()
	updateDone := make(chan struct{})
	go func() {
		s.SetOAuthEgressOverride(true)
		close(updateDone)
	}()
	s.runtimeStateMu.Unlock()

	<-activateDone
	<-updateDone

	active := s.active.Load()
	if active != newGen {
		t.Fatalf("active generation = %p, want new generation %p", active, newGen)
	}
	if !active.proxy.OAuthEgressOverride() {
		t.Fatal("activating generation lost the concurrent OAuth egress override hot update")
	}
}
