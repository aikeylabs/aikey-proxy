package mcp

// isolation.go — 🔴 the price of running the MCP plane in the LLM plane's
// process (D-1 / requirement R12).
//
// # Why this file is load-bearing
//
// Mounting /mcp/* on the shared port was chosen deliberately (see doc.go). The
// argument for it only holds if a fault in this new, unproven code cannot reach
// the forwarding path a customer's whole engineering org depends on. That is
// what the shell below buys, and the two fences that prove it — inject a panic
// (1.F2), leak goroutines until the budget is gone (1.F3) — are the acceptance
// criteria for the deployment shape itself, not nice-to-have tests.
//
// # The three failure modes it contains, and why each needs its own mechanism
//
//	panic          a nil map write in a manifest parser must not kill the
//	               process. Go's http.Server recovers per-connection, but it
//	               closes the connection abruptly and the shared
//	               recoverMiddleware cannot tell an MCP fault from an LLM one.
//	               Recovering HERE gives the operator a distinct event name and
//	               lets the client see a clean JSON-RPC error.
//	saturation     a slow upstream MCP server will pile up in-flight requests.
//	               Without a private budget those goroutines and their buffers
//	               are drawn from the same process the LLM path lives in. The
//	               semaphore caps the blast radius; shedding is the CORRECT
//	               behaviour, and it is logged so it is not silent.
//	slowness       an upstream that accepts the connection and then never
//	               answers holds a slot forever. The timeout closes that.
//
// 🔴 Shedding must stay LOUD. A plane that silently drops requests when busy is
// indistinguishable from one that is broken, and the operator's first hypothesis
// will be the wrong one.

import (
	"context"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/fallbackpolicy"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// DefaultPlaneConcurrency is the MCP plane's private in-flight budget.
//
// 🔴 The number matters less than the fact that it is SEPARATE and FINITE.
// 64 is sized so a Personal-edition laptop hosting a handful of stdio backends
// never touches it, while a runaway upstream on a Production node is capped
// long before the process feels it.
const DefaultPlaneConcurrency = 64

// DefaultPlaneTimeout is the fallback per-request ceiling used when no
// fallbackpolicy layer answers.
//
// 🔴 It is only a FALLBACK. The real value comes from
// fallbackpolicy.Resolve(...).UpstreamAttemptTimeout, which carries a Source so
// "where did this number come from" is always answerable. 🚫 Do not add a
// second configuration ladder for MCP — that was the explicit instruction in
// tasks 6.2, and pkg/fallbackpolicy exists precisely so there is one.
const DefaultPlaneTimeout = 60 * time.Second

// PlaneStats is the isolation shell's observable state, surfaced by
// GET /health/mcp.
//
// 🔴 InFlight and Rejected are reported separately on purpose. "Busy" and
// "shedding" are different operational situations: the first is normal load,
// the second says a limit was actually hit. Collapsing them into one gauge is
// how a saturation incident gets read as healthy traffic.
type PlaneStats struct {
	// Limit is the configured concurrency budget.
	Limit int `json:"limit"`
	// InFlight is the number of MCP requests being served right now.
	InFlight int `json:"in_flight"`
	// Rejected counts requests shed because the budget was full, since start.
	Rejected uint64 `json:"rejected_total"`
	// PanicsRecovered counts panics contained by this shell, since start.
	//
	// 🔴 Non-zero is ALWAYS a defect in the MCP plane, even if every request
	// still succeeded. It is surfaced rather than merely logged so a release
	// gate can assert on it.
	PanicsRecovered uint64 `json:"panics_recovered_total"`
	// TimeoutMs is the effective per-request ceiling.
	TimeoutMs int64 `json:"timeout_ms"`
	// TimeoutSource says which layer supplied TimeoutMs — org / local_yaml /
	// builtin. Part of the contract, not a debug field: an operator changing an
	// org policy needs to see whether it actually took.
	TimeoutSource string `json:"timeout_source"`
}

// Isolation is the shell every MCP HTTP handler runs inside.
//
// The zero value is not usable; construct with NewIsolation.
type Isolation struct {
	sem   chan struct{}
	limit int
	// resolve returns the CURRENT effective policy.
	//
	// 🔴 A function, not a snapshot taken at construction. The org's fallback
	// policy arrives on the 60s poll, which starts AFTER the listener is
	// serving — so a value captured at build time would be the builtin
	// default forever, and an admin who later set a timeout would see it
	// accepted by the console and silently never applied. "Configured but
	// never applied" is the failure mode this repo has already paid for more
	// than once; a live read costs one atomic load per request.
	resolve func() fallbackpolicy.Effective

	inFlight atomic.Int64
	rejected atomic.Uint64
	panicked atomic.Uint64
	logger   *slog.Logger
}

// NewIsolation builds the shell.
//
// resolvePolicy returns the live effective policy; pass nil in contexts that
// genuinely have none (Personal edition has no control plane at all), and the
// builtin defaults apply through the same three-state resolution the LLM plane
// uses. 🚫 Do not add a second configuration ladder for MCP — pkg/fallbackpolicy
// exists so there is exactly one, and it carries a Source so "where did this
// number come from" is always answerable.
func NewIsolation(limit int, resolvePolicy func() fallbackpolicy.Effective, logger *slog.Logger) *Isolation {
	if limit <= 0 {
		limit = DefaultPlaneConcurrency
	}
	if logger == nil {
		logger = slog.Default()
	}
	if resolvePolicy == nil {
		resolvePolicy = func() fallbackpolicy.Effective {
			return fallbackpolicy.Resolve(nil, fallbackpolicy.LocalOverrides{})
		}
	}
	return &Isolation{
		sem:     make(chan struct{}, limit),
		limit:   limit,
		resolve: resolvePolicy,
		logger:  logger,
	}
}

// effectiveTimeout reads the current per-request ceiling and its provenance.
func (iso *Isolation) effectiveTimeout() (time.Duration, string) {
	r := iso.resolve().UpstreamAttemptTimeout
	timeout := time.Duration(r.Value) * time.Millisecond
	source := string(r.Source)
	if timeout <= 0 {
		// 🔴 A resolved 0 means the admin explicitly chose "no per-attempt
		// ceiling" for the LLM path. The MCP plane cannot honour that: an
		// unbounded MCP request holds one of a FINITE number of plane slots, so
		// "no timeout" degrades into "the plane wedges shut" — a different and
		// worse outcome than the one the admin asked for. The floor is applied
		// and made VISIBLE in the source string rather than pretending the
		// admin's 0 was never set.
		timeout = DefaultPlaneTimeout
		source += "+mcp_floor"
	}
	return timeout, source
}

// Stats snapshots the shell for /health/mcp.
func (iso *Isolation) Stats() PlaneStats {
	timeout, source := iso.effectiveTimeout()
	return PlaneStats{
		Limit:           iso.limit,
		InFlight:        int(iso.inFlight.Load()),
		Rejected:        iso.rejected.Load(),
		PanicsRecovered: iso.panicked.Load(),
		TimeoutMs:       timeout.Milliseconds(),
		TimeoutSource:   source,
	}
}

// Timeout returns the effective per-request ceiling as of now.
func (iso *Isolation) Timeout() time.Duration {
	t, _ := iso.effectiveTimeout()
	return t
}

// Wrap returns an http.Handler that runs next inside the shell.
//
// Order matters and is not arbitrary:
//
//  1. panic recovery OUTSIDE everything, so a panic raised while acquiring or
//     releasing the semaphore is still contained;
//  2. semaphore acquisition, so a shed request costs almost nothing;
//  3. the timeout context, so the clock starts when work actually starts and a
//     request queued behind the budget is not penalised for waiting.
//
// 🔴 Getting (2) and (3) the other way round is a classic subtle bug: the
// timeout would then cover queueing time, so under load every request would
// fail with a timeout that has nothing to do with the upstream, and the logs
// would blame the backend.
func (iso *Isolation) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer iso.recoverPanic(w, r)

		select {
		case iso.sem <- struct{}{}:
		default:
			iso.rejected.Add(1)
			// 🔴 Loud on purpose. Shedding is the isolation shell doing its job,
			// but an operator who cannot see it happening will diagnose the
			// resulting client errors as an upstream fault.
			iso.logger.WarnContext(r.Context(),
				"MCP plane shed a request: its private concurrency budget is full. "+
					"This protects the LLM forwarding path; investigate the slow MCP backend.",
				"event.name", observability.EventProxyMCPPlaneRejected,
				"limit", iso.limit,
				"path", r.URL.Path,
			)
			writeRPCHTTPError(w, nil, mcpwire.ErrRateLimited,
				"The MCP plane is at its concurrency limit. Retry shortly; if this persists, an MCP backend is responding slowly.",
				nil)
			return
		}
		defer func() { <-iso.sem }()

		iso.inFlight.Add(1)
		defer iso.inFlight.Add(-1)

		timeout, _ := iso.effectiveTimeout()
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// recoverPanic contains a panic escaping an MCP handler.
//
// It deliberately does NOT re-panic. The shared server has its own recovery
// (internal/observability), but letting the panic reach it would (a) lose the
// MCP-specific event name, and (b) drop the connection instead of returning a
// JSON-RPC error the client can render. Both make the fault harder to attribute
// to the MCP plane, which is the one thing the isolation bargain must make easy.
func (iso *Isolation) recoverPanic(w http.ResponseWriter, r *http.Request) {
	rec := recover()
	if rec == nil {
		return
	}
	iso.panicked.Add(1)
	iso.logger.ErrorContext(r.Context(),
		"panic recovered inside the MCP plane; the LLM forwarding path is unaffected",
		"event.name", observability.EventProxyMCPPanicRecovered,
		"panic", rec,
		"path", r.URL.Path,
		"stack", string(debug.Stack()),
	)
	// 🔴 NOT an EXT_ code. A panic is OUR defect; labelling it as an upstream
	// failure would send the customer to debug their own MCP server.
	// writeInternalError emits plain JSON-RPC -32603, which is the honest
	// vocabulary for "something broke inside AiKey".
	//
	// If the handler already began writing, the headers are gone and this write
	// is a no-op beyond the log line — the abrupt body end is then the signal.
	writeInternalError(w, nil,
		"The MCP gateway encountered an internal error handling this request. "+
			"This is a defect in AiKey, not in your MCP backend; the surrounding log line carries the detail.")
}
