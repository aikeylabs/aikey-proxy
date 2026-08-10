// fallback_policy_rail.go — the upstream-fallback threshold rail (openspec change
// `aliyun-aigw-p0-upstream-fallback`, tasks 1b.4 / 1b.4b / 1b.5).
//
// # 🔴 Why this is a DECLARATION and not a loop
//
// Task 1b.4's stated discipline is 「不手写第六个轮询循环」, and the reason is a
// specific incident: on 2026-07-03 two hand-written pollers evaluated their
// preconditions ONCE at startup, early-returned forever, and starved silently for
// seven hours with zero log lines. The bug was invisible because a loop that never
// runs looks exactly like a loop with nothing to do.
//
// The SyncRail framework (railset.go) makes both of those failures structural
// rather than optional:
//   - gate, control URL and credential are re-evaluated EVERY cycle, so a
//     precondition that becomes true later is picked up;
//   - failures are counted into OK → STALE(3) → OFFLINE(20), so a rail in trouble
//     announces itself instead of going quiet;
//   - the data path keeps using the last known good value throughout.
//
// So this file adds a sixth FOLLOWER — a railSpec, a gate and a sync function.
// There is no ticker here on purpose.
//
// # 🔴 Conditional request first, then the short period (task 1b.4b)
//
// The period is 10 seconds because the thing it fixes is human: an administrator
// watching a "delivered to N/M nodes" badge treats a minute of no movement as
// broken. But control-master has no push channel to the proxy (verified — there
// is none), so the only option is asking, and asking must therefore be cheap.
//
// 200 seats polling every 10s is ~20 requests/second against a CUSTOMER's master,
// running on the customer's hardware. That is affordable ONLY with the 304 path:
// the server answers from a single integer without reading the thresholds. Landing
// the shorter period first would have multiplied that customer's load by six for
// no benefit, which is why the ordering is a safety property and not a preference.
//
// 🚫 The period is deliberately not configurable. Five thresholds are the product
// surface; the poll period is an implementation detail, and exposing it invites
// operators to tune a number they have no information about.
//
// # 🔴 Non-secret material only (task 1b.5)
//
// This rail carries five integers. Upstream ADDRESSES and key ciphertext keep
// traveling on the delivery snapshot, where the encryption boundary already
// lives. The response is asserted secret-free on arrival — not because five int64
// pointers can hold a key today, but so that stays true when somebody later adds
// "just one string field". The door is one-way: once a secret has gone out over a
// side channel, rotation is the only remedy.
package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/AiKeyLabs/pkg/fallbackpolicy"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// fallbackPolicyPollInterval — 🔴 10 seconds, and this rail only. `railSpec.interval`
// is per-rail by design, so the other five keep their own cadence: this change
// must not quietly re-time anything it did not set out to change.
const fallbackPolicyPollInterval = 10 * time.Second

// maxFallbackPolicyBody caps the response read. A policy is a few hundred bytes;
// anything larger means we are talking to something that is not this endpoint,
// and reading it unbounded would let a misrouted response consume memory.
const maxFallbackPolicyBody = 64 << 10

// fallbackPolicyNodeHeader carries the polling node's cluster id so the control
// plane can count MACHINES rather than accounts (see syncFallbackPolicy).
//
// 🚫 Not an identity claim and never used for authorization — the bearer token
// already decided who may read this org's policy. This only splits an already-
// authorized caller into the nodes it is made of, so the worst a wrong value can
// do is miscount a display number for a tenant that could read it anyway.
const fallbackPolicyNodeHeader = "X-Aikey-Node-Id"

const (
	clusterControlServiceTokenEnv = "AIKEY_CONTROL_SERVICE_TOKEN"
	clusterOrgIDEnv               = "AIKEY_HUB_ORG_ID"
)

var fallbackPolicyHTTPClient = httpx.NewSwappableDirect(10 * time.Second)

// fallbackPolicyRail declares the rail.
//
// Gate: the cache must exist. 🔴 Note what is NOT gated — there is no
// `if edition == personal` here. Personal simply has no control URL, so the
// framework skips the cycle without counting a failure, and every threshold
// resolves to its builtin default through the same code path the other editions
// use. That is task 1b.11's requirement expressed structurally rather than by
// branching on edition.
func (s *Supervisor) fallbackPolicyRail() railSpec {
	return railSpec{
		name:     "fallback_policy",
		interval: fallbackPolicyPollInterval,
		// 🔴 A cluster worker has NO team JWT and never will: that credential is
		// minted from a vault refresh token written by `aikey login`, and nobody
		// logs in on a node. Requiring one made this rail fail every cycle on
		// every worker, so all five thresholds resolved to `source: builtin` and
		// an administrator's saved change reached nothing in the fleet. On a node
		// the sync below authenticates with the node service token instead.
		needsTeamJWT: !s.isClusterNode(),
		gate: func(_ *generation) bool {
			return s.fallbackPolicy != nil
		},
		sync: s.syncFallbackPolicy,
	}
}

// localAttemptTimeoutMs derives the local-yaml layer for the per-attempt timeout
// (task 1b.7) — and currently returns nil, deliberately.
//
// 🔴 A SHAPE MISMATCH worth stating rather than papering over. Task 1b.7 names
// `providers.<name>.timeout` as this threshold's local layer, but the two are not
// the same shape:
//
//	providers.<name>.timeout    PER PROVIDER. Builds that provider's HTTP client,
//	                            and different providers may legitimately differ.
//	upstream_attempt_timeout_ms PER ATTEMPT along one chain, which may span several
//	                            providers.
//
// Collapsing a map of per-provider values into one number requires choosing: the
// max? the min? the one belonging to the hop we are about to try? Each answer is
// defensible and each produces a DIFFERENT effective timeout — and reporting any of
// them as `source: local_yaml` would make `/status` assert a number the operator
// never wrote. That is precisely the "展示 = 执行" failure this phase exists to
// prevent, so inventing a rule here would undo the point.
//
// Until that is decided, this returns nil and the behavior is honest:
//   - the per-provider yaml timeouts KEEP working exactly as they do today, at the
//     HTTP-client layer where they have always lived;
//   - the chain-level threshold resolves org → builtin, and `/status` reports
//     `org` or `builtin` — never a `local_yaml` it cannot substantiate.
//
// 🔴 Recorded as an open question rather than a TODO, because picking silently is
// the failure mode. See p1b-policy-rail-closure.md.
func localAttemptTimeoutMs(_ *config.Config) *int64 { return nil }

// FallbackPolicyCache exposes the threshold cache for the health surface. nil on a
// build where the capability is not wired, which the /status block reports honestly
// by being absent rather than by showing defaults with no explanation.
func (s *Supervisor) FallbackPolicyCache() *proxy.FallbackPolicyCache { return s.fallbackPolicy }

// fallbackPolicyWire mirrors the control plane's response. Pointers throughout, so
// "not configured" survives the wire as absence rather than becoming 0 (I22).
type fallbackPolicyWire struct {
	Version int64                 `json:"version"`
	Policy  fallbackpolicy.Policy `json:"policy"`
}

// syncFallbackPolicy performs one conditional pull.
//
// Returns nil on success INCLUDING a 304 — "fetched, nothing changed" is a
// successful cycle, and the framework treats a nil error as OK. Any error is
// counted and surfaced, and the cache is left untouched: keep-last-known means a
// control-plane blip never re-times requests in the fleet.
//
// 🔴 A failure here is NOT a reason to refuse service (task 1b.4). If the policy
// has never been pulled, the resolver falls through to builtin defaults and the
// health endpoint says so. Refusing requests because a configuration poll failed
// would convert a cosmetic problem into an outage.
func (s *Supervisor) syncFallbackPolicy(ctx context.Context, _ *generation, masterURL, bearer string) error {
	cache := s.fallbackPolicy
	if cache == nil {
		return nil
	}

	// Node vs seat. The representation is identical (same ETag, same body); only
	// the surface and the credential differ, because the two callers can prove
	// who they are in different ways.
	url := masterURL + "/v1/fallback-policy"
	if s.isClusterNode() {
		orgID, ok := s.clusterOrgID()
		if !ok {
			// 🔴 Not an error: a node that has not yet pulled any key genuinely
			// does not know its org. Counting it as a failure would make a
			// still-provisioning worker report a broken sync rail. It keeps its
			// builtin defaults and the next cycle retries.
			return nil
		}
		controlToken := s.clusterControlServiceToken()
		if controlToken == "" {
			// No control-plane credential provisioned yet. Same posture as an
			// unknown org: stay on builtin defaults rather than send a token the
			// control plane will reject on every cycle.
			return nil
		}
		url = masterURL + "/internal/org/" + orgID + "/fallback-policy"
		// 🔴 The CONTROL token, not Cluster.ServiceToken — that one is the hub's,
		// and the control plane answers it 401.
		bearer = controlToken
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("build fallback-policy request: %w", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	// Who is polling, for the console's rollout count (task 4.23).
	//
	// 🔴 Every worker in a cluster presents the SAME control_service_token, so
	// the control plane cannot tell two nodes apart from the credential — it was
	// counting distinct ACCOUNTS, which collapses an N-worker fleet to 1. A
	// fully-synced 2-worker staging cluster reported "已下发到 1/18 台机器"
	// (2026-08-04), i.e. the console said the policy had not rolled out while
	// both nodes were serving it. Node id is the only thing that distinguishes
	// them, and only the node knows it.
	//
	// Seat installs deliberately send nothing: there the account IS the machine,
	// and the server keeps its existing per-account counting for them.
	if s.isClusterNode() && s.cfg.Cluster.NodeID != "" {
		req.Header.Set(fallbackPolicyNodeHeader, s.cfg.Cluster.NodeID)
	}
	// 🔴 The conditional request. Without this header the server must read and
	// serialize the whole policy every 10 seconds for every seat.
	if v := cache.Version(); v > 0 || cache.Synced() {
		req.Header.Set("If-None-Match", fallbackPolicyETag(v))
	}

	resp, err := fallbackPolicyHTTPClient.Get().Do(req)
	if err != nil {
		return fmt.Errorf("fetch fallback policy: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// 🔴 Advance last_success_at even though nothing moved: a 304 proves the
		// control plane is reachable. Without this, a fleet whose policy is simply
		// stable would look ever more stale and an operator would go hunting for a
		// sync failure that is not happening.
		cache.TouchSuccess()
		return nil
	case http.StatusOK:
		// fall through
	default:
		return fmt.Errorf("fallback policy: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFallbackPolicyBody))
	if err != nil {
		return fmt.Errorf("read fallback policy: %w", err)
	}
	// 🔴 Task 1b.5 — check on ARRIVAL too, not only where it is served. The two
	// repos deploy independently, so a control plane that starts leaking material
	// must not be able to persuade this side to cache and log it.
	if err := fallbackpolicy.AssertNoSecretShaped(string(body)); err != nil {
		return fmt.Errorf("fallback policy payload rejected: %w", err)
	}

	var wire fallbackPolicyWire
	if err := json.Unmarshal(body, &wire); err != nil {
		return fmt.Errorf("decode fallback policy: %w", err)
	}
	// 🔴 Validate what arrived. The control plane validates on write, but this
	// proxy may be talking to an older or a misconfigured one, and a budget below
	// the attempt timeout would make every chain dead on arrival. Rejecting keeps
	// the last known good policy — visibly, via the failure counter.
	if err := wire.Policy.Validate(); err != nil {
		return fmt.Errorf("fallback policy failed validation: %w", err)
	}

	previous := cache.Version()
	policy := wire.Policy
	cache.Store(&policy, wire.Version)
	if previous != wire.Version {
		eff := cache.Snapshot()
		slog.Info("fallback policy updated",
			"event.name", "proxy.fallback_policy.changed",
			"version", wire.Version,
			"attempt_timeout_ms", eff.UpstreamAttemptTimeout.Value,
			"attempt_timeout_source", string(eff.UpstreamAttemptTimeout.Source),
			"chain_budget_ms", eff.ChainTotalBudget.Value,
			"cooldown_ms", eff.BindingCooldown.Value,
			"idle_gap_ms", eff.IdleGap.Value,
			"max_stickiness_ms", eff.MaxStickiness.Value)
	}
	return nil
}

// fallbackPolicyETag must match the control plane's rendering exactly. Kept as a
// one-liner beside its only caller rather than shared, because the two sides are
// deployed separately and a shared helper would imply a coupling that does not
// exist — the wire contract is the ETag STRING, and the fence in the handler test
// pins that string on the server side.
func fallbackPolicyETag(version int64) string {
	return `"fbp-` + itoa64(version) + `"`
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// isClusterNode reports whether this proxy is a cluster worker holding a node
// service token — the only identity a worker can present to the control plane.
func (s *Supervisor) isClusterNode() bool {
	return s.cfg != nil && s.cfg.Cluster.Enabled && s.clusterControlServiceToken() != ""
}

// clusterControlServiceToken resolves the same two configuration forms the
// cluster node ships with. Production installers render the token into YAML;
// the Docker/systemd node environment also exports it for the daemon. The env
// fallback keeps policy sync alive during version skew where an older rendered
// YAML lacks the newer field. The secret is never logged.
func (s *Supervisor) clusterControlServiceToken() string {
	if s != nil && s.cfg != nil {
		if token := strings.TrimSpace(s.cfg.Cluster.ControlServiceToken); token != "" {
			return token
		}
	}
	return strings.TrimSpace(os.Getenv(clusterControlServiceTokenEnv))
}

// clusterOrgID is the organization this node serves, from configuration.
//
// 🔴 Deliberately NOT derived from the vault. The first attempt did exactly
// that — a node serves one org, so read it off the cache — and a staging worker
// disproved it: its cache held LIVE keys from two organizations (101 rows and
// 3, the minority ones `synced_inactive`, not stale), so no filter makes the
// answer unambiguous. Since this value selects whose thresholds the node
// enforces, inferring it would mean governing one tenant's traffic with
// another's numbers, and it would look correctly configured while doing so.
func (s *Supervisor) clusterOrgID() (string, bool) {
	if s == nil || s.cfg == nil || !s.cfg.Cluster.Enabled {
		return "", false
	}
	orgID := strings.TrimSpace(s.cfg.Cluster.OrgID)
	if orgID == "" {
		// This environment value is already the authority used by the daemon and
		// other org-scoped rails. It is configured state, not a vault inference.
		orgID = strings.TrimSpace(os.Getenv(clusterOrgIDEnv))
	}
	return orgID, orgID != ""
}
