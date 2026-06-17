package conversation_audit

// registration.go — init()-time observer registration + dependency injection.
//
// Wiring (mirrors ndjson_fanout's pattern):
//
//	main.go blank-imports this package → init() registers the descriptor
//	  (no deps yet — they don't exist until the proxy builds its outbox).
//	supervisor wiring builds the content WAL + seq allocator + content
//	  reporter, constructs a RecordSink over them, and calls SetDeps(...)
//	  BEFORE supervisor.BuildObservers runs.
//	BuildObservers calls build() → reads the injected deps → constructs the
//	  observer. If deps are absent (feature not wired for this edition), build
//	  returns an error and the framework skips the observer (proxy still starts).
//
// Why a package-local SetDeps instead of a framework global: the sink bridges
// the events package (ContentWAL / SeqAllocator / ContentReporter) which this
// decoupled observer must not import. The supervisor owns both sides, so it
// constructs the bridge and injects it here — keeping the coupling contained,
// exactly as ndjson_fanout does for its vault bridge.

import (
	"fmt"
	"sync"

	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

const (
	// observerName is the unique registry key (RegisterObserver enforces
	// uniqueness; the slug may be shared with other proxy-core observers).
	observerName = "conversation-audit"
	// ownerSlug is the synthetic proxy-core first-party slug — already in
	// observer.FirstPartyAllowlist and special-cased always-on by the
	// supervisor enable check (the observer self-gates on the org policy via
	// WantsFullPayload/Enabled, so always-built is correct).
	ownerSlug = "aikey-proxy-core"
)

// Deps are the live dependencies the supervisor injects before BuildObservers.
type Deps struct {
	Sink     RecordSink  // durable outbox bridge (content WAL + seq + reporter)
	Enabled  func() bool // live conversation_audit_enabled for this proxy's tenant
	MaxBytes func() int  // live per-field content cap
}

var (
	depsMu sync.RWMutex
	deps   *Deps
)

// SetDeps is the wiring entry point. Called by the supervisor after the content
// outbox is built and before BuildObservers. A nil Sink leaves the observer
// unbuildable (build returns an error → framework skips it).
func SetDeps(d Deps) {
	depsMu.Lock()
	defer depsMu.Unlock()
	deps = &d
}

func currentDeps() *Deps {
	depsMu.RLock()
	defer depsMu.RUnlock()
	return deps
}

func init() {
	observer.RegisterObserver(observer.Observer{
		Name:         observerName,
		OwnerAppSlug: ownerSlug,
		// MVP scope: employee chat = user_chat only. App-pipeline (first-party
		// app) content audit is deliberately out of scope for this iteration.
		Streams: []string{observer.StreamUserChat},
		Build:   build,
	})
}

// build is the Observer.Build callback, invoked once at proxy startup.
func build(_ map[string]any) (observer.StreamingObserver, error) {
	d := currentDeps()
	if d == nil || d.Sink == nil {
		return nil, fmt.Errorf("conversation_audit: deps not wired (SetDeps not called or nil sink)")
	}
	return New(Config{
		Sink:     d.Sink,
		Enabled:  d.Enabled,
		MaxBytes: d.MaxBytes,
	}), nil
}
