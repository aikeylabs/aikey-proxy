package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// Provider-path health is intentionally separate from poolCooldown. A request
// that received no HTTP response proves only that its DNS/TCP/TLS/egress path
// failed; it does not prove that the selected OAuth account is unhealthy.
const (
	pathStateSuspect  = "suspect"
	pathStateHalfOpen = "half_open"
	pathStateOpen     = "open"

	pathFailureTransport  = "transport"
	pathFailureEgressDial = "egress_dial"
)

var pathRetryBackoff = [...]time.Duration{
	time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	10 * time.Second,
}

// ProviderPath is the non-secret identity of one outbound route. Key and
// OriginFingerprint are hashes; EgressFingerprint reuses the established
// egress-attribution hash. Raw base URLs and egress specs never leave this type's
// constructor.
type ProviderPath struct {
	Key               string
	Provider          string
	Protocol          string
	Transport         string
	OriginFingerprint string
	EgressFingerprint string
}

// ProviderPathHealth is safe for logs and /status. It deliberately contains no
// account identity, token, raw upstream URL, or raw egress configuration.
type ProviderPathHealth struct {
	PathID              string `json:"path_id"`
	Provider            string `json:"provider"`
	Protocol            string `json:"protocol"`
	Transport           string `json:"transport"`
	OriginFingerprint   string `json:"origin_fingerprint"`
	EgressFingerprint   string `json:"egress_fingerprint,omitempty"`
	State               string `json:"state"`
	FailureClass        string `json:"failure_class"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	RetryAfterSeconds   int    `json:"retry_after_seconds,omitempty"`
}

// ProviderPathPermit is the result of the hot-path circuit-breaker gate.
type ProviderPathPermit struct {
	Allowed    bool
	Probe      bool
	RetryAfter time.Duration
	Health     ProviderPathHealth
}

type providerPathDecision struct {
	path       ProviderPath
	overrideOn bool
}

type providerPathEntry struct {
	path          ProviderPath
	state         string
	failureClass  string
	failures      int
	nextProbeAt   time.Time
	probeInFlight bool
}

// ProviderPathHealthManager is shared by every Proxy generation owned by one
// Supervisor. State survives configuration reloads but remains node-local and
// in-memory: it is a live circuit breaker, not durable account truth.
type ProviderPathHealthManager struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*providerPathEntry
}

func NewProviderPathHealthManager() *ProviderPathHealthManager {
	return &ProviderPathHealthManager{
		now:     time.Now,
		entries: make(map[string]*providerPathEntry),
	}
}

// Permit allows normal traffic on a healthy path and single-flights recovery
// probes for suspect/open paths. A "probe" is the next real user request; no
// background inference request is generated.
func (m *ProviderPathHealthManager) Permit(path ProviderPath) ProviderPathPermit {
	if m == nil || path.Key == "" {
		return ProviderPathPermit{Allowed: true}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	e := m.entries[path.Key]
	if e == nil {
		return ProviderPathPermit{Allowed: true}
	}
	now := m.now()
	switch e.state {
	case pathStateSuspect:
		if !e.probeInFlight {
			e.state = pathStateHalfOpen
			e.probeInFlight = true
			return ProviderPathPermit{Allowed: true, Probe: true, Health: m.healthLocked(e, now)}
		}
	case pathStateOpen:
		if !e.probeInFlight && !now.Before(e.nextProbeAt) {
			e.state = pathStateHalfOpen
			e.probeInFlight = true
			return ProviderPathPermit{Allowed: true, Probe: true, Health: m.healthLocked(e, now)}
		}
	}

	retry := e.nextProbeAt.Sub(now)
	if retry < time.Second {
		retry = time.Second
	}
	return ProviderPathPermit{Allowed: false, RetryAfter: retry, Health: m.healthLocked(e, now)}
}

// NoteTransportFailure records a failure that happened before any HTTP response.
// The first failure is suspect; a second consecutive failure opens the breaker.
func (m *ProviderPathHealthManager) NoteTransportFailure(path ProviderPath, failureClass string) ProviderPathHealth {
	if m == nil || path.Key == "" {
		return ProviderPathHealth{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	e := m.entries[path.Key]
	if e == nil {
		e = &providerPathEntry{path: path}
		m.entries[path.Key] = e
	}
	e.path = path
	e.failureClass = failureClass
	e.failures++
	e.probeInFlight = false
	if e.failures == 1 {
		e.state = pathStateSuspect
		e.nextProbeAt = now
	} else {
		e.state = pathStateOpen
		e.nextProbeAt = now.Add(pathBackoff(e.failures))
	}
	return m.healthLocked(e, now)
}

// NoteHTTPResponse closes the path breaker for every HTTP status. Once headers
// arrived, reachability is proven; 401/429/5xx are classified by account/provider
// logic separately.
func (m *ProviderPathHealthManager) NoteHTTPResponse(path ProviderPath) {
	if m == nil || path.Key == "" {
		return
	}
	m.mu.Lock()
	delete(m.entries, path.Key)
	m.mu.Unlock()
}

// NoteProbeCanceled releases a half-open slot when the client canceled. A
// cancellation is not evidence that the path failed and does not increment the
// breaker.
func (m *ProviderPathHealthManager) NoteProbeCanceled(path ProviderPath) {
	if m == nil || path.Key == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.entries[path.Key]; e != nil && e.state == pathStateHalfOpen {
		e.state = pathStateOpen
		e.probeInFlight = false
		e.nextProbeAt = m.now()
	}
}

// NotifyInputsChanged makes every unhealthy path immediately eligible for one
// half-open real request. Called for host-network fingerprint changes and live
// node transport/egress-override updates.
func (m *ProviderPathHealthManager) NotifyInputsChanged() {
	if m == nil {
		return
	}
	m.mu.Lock()
	now := m.now()
	for _, e := range m.entries {
		e.state = pathStateOpen
		e.probeInFlight = false
		e.nextProbeAt = now
	}
	m.mu.Unlock()
}

func (m *ProviderPathHealthManager) Snapshot() []ProviderPathHealth {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := make([]ProviderPathHealth, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, m.healthLocked(e, now))
	}
	sortProviderPathHealth(out)
	return out
}

func (m *ProviderPathHealthManager) healthLocked(e *providerPathEntry, now time.Time) ProviderPathHealth {
	retry := e.nextProbeAt.Sub(now)
	return ProviderPathHealth{
		PathID:              shortHash(e.path.Key),
		Provider:            e.path.Provider,
		Protocol:            e.path.Protocol,
		Transport:           e.path.Transport,
		OriginFingerprint:   e.path.OriginFingerprint,
		EgressFingerprint:   e.path.EgressFingerprint,
		State:               e.state,
		FailureClass:        e.failureClass,
		ConsecutiveFailures: e.failures,
		RetryAfterSeconds:   durationSecondsCeil(retry),
	}
}

func pathBackoff(failures int) time.Duration {
	idx := failures - 2
	if idx < 0 {
		return 0
	}
	if idx >= len(pathRetryBackoff) {
		idx = len(pathRetryBackoff) - 1
	}
	return pathRetryBackoff[idx]
}

func durationSecondsCeil(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}

func providerPathForRoute(route *vkeys.ResolvedRoute, overrideOn bool) ProviderPath {
	if route == nil {
		return ProviderPath{}
	}
	providerCode := providerCanonicalCode(route.ProviderCode)
	if providerCode == "" {
		providerCode = providerCanonicalCode(route.Provider)
	}
	protocol := strings.TrimSpace(route.ProtocolType)
	if protocol == "" {
		protocol = strings.TrimSpace(route.Provider)
	}
	origin := normalizedOrigin(route.BaseURL)
	originFingerprint := shortHash(origin)
	applied, engine, egressFingerprint := egressAttribution(route.EgressProxyURL, overrideOn)
	transport := "node"
	if applied {
		transport = engine
	} else {
		egressFingerprint = ""
	}
	rawKey := strings.Join([]string{providerCode, protocol, origin, transport, egressFingerprint}, "|")
	return ProviderPath{
		Key:               hashString(rawKey),
		Provider:          providerCode,
		Protocol:          protocol,
		Transport:         transport,
		OriginFingerprint: originFingerprint,
		EgressFingerprint: egressFingerprint,
	}
}

func providerPathDecisionForRequest(ctx context.Context, route *vkeys.ResolvedRoute, currentOverride bool) providerPathDecision {
	if ctx != nil {
		if pinned, ok := ctx.Value(ctxKeyProviderPathDecision).(providerPathDecision); ok && pinned.path.Key != "" {
			return pinned
		}
	}
	return providerPathDecision{path: providerPathForRoute(route, currentOverride), overrideOn: currentOverride}
}

func normalizedOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "invalid"
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func shortHash(s string) string {
	return hashString(s)[:12]
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sortProviderPathHealth(items []ProviderPathHealth) {
	sort.Slice(items, func(i, j int) bool { return items[i].PathID < items[j].PathID })
}
