// license_plane_rail.go — carries the deployment's forwarding gate from the
// control plane to this proxy's request path.
//
// # The problem, in one sentence
//
// licstate has always answered "may this deployment forward" — `expired`,
// `grace_exhausted`, `revoked` and `stale` all carry `Forwarding: deny`, the
// control service projects that verdict, and it serves it on
// `GET /v1/license/plane` under a comment that names the proxy as its reader.
// The proxy never read it, so a customer whose license expired kept forwarding
// every request indefinitely while their console correctly showed `expired`.
//
// 🔴 Why nobody noticed, which is the part worth keeping: every layer of this
// mechanism fails OPEN on purpose, and correctly so — PlaneGate starts `allow`
// so licensing can never stop a healthy deployment at start-up. The consequence
// is that "the consumer was never written" and "everything is licensed" produce
// identical observable behavior. There was no red to see. aikey-proxy even had a
// green fence asserting the hot path does not import licensing, which was true
// for the wrong reason. The replacement is a POSITIVE fence — see
// internal/proxy/hotpath_license_gate_fence_test.go.
//
// See workflow/CI/bugfix/20260827-forwarding-gate-was-never-wired.md.
//
// # Why a rail, and not a loop
//
// railset.go exists because six hand-written pollers drifted apart and two of
// them starved silently for seven hours (bugfix
// 2026-07-03-routing-override-rail-silent-stall.md). Declaring a railSpec buys
// the per-cycle re-evaluation of gate / control URL / credential, the
// OK→STALE→OFFLINE visibility state machine, /status exposure and panic
// isolation — and this rail may not opt out of any of it. A licensing rail that
// starved silently would restore the exact defect this change exists to fix.
//
// # Why two endpoints rather than one
//
// The gate has to reach every edition's forwarding proxy, and they cannot all
// prove who they are the same way:
//
//	Cluster     a node holds the deployment's control SERVICE token and never has
//	            a team JWT — nobody runs `aikey login` on a worker. It reads
//	            /v1/license/plane, the full projection.
//	Production  the proxy runs on an employee's machine with a member's team JWT
//	Trial       and no service token. It reads /v1/license/plane/member, which
//	            carries the gate and nothing else — a member has no business
//	            seeing the deployment's commercial standing (PRD §6.4).
//	Personal    has no control URL, so the framework skips the cycle and the gate
//	            is never populated. 🚫 Note there is no `if edition == personal`
//	            anywhere below: the absence of a control plane already expresses
//	            it, the same way fallbackPolicyRail handles it.
package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// licensePlanePollInterval bounds how long this proxy keeps forwarding after the
// control plane has stopped permitting it.
//
// 60s matches keyRevocationPollInterval deliberately: "a suspension takes effect
// within a minute" and "an expiry takes effect within a minute" are the same
// promise, and an operator should have one number to remember rather than two.
//
// 🚫 Deliberately not configurable, for the reason the revocation rail gives:
// how quickly an authorization decision reaches the data path is a security
// property of the deployment, not a knob for the party who benefits from
// widening it.
const licensePlanePollInterval = 60 * time.Second

const (
	// licensePlanePath is the full projection, for a caller holding the service
	// token (Cluster nodes).
	licensePlanePath = "/v1/license/plane"
	// licenseMemberPlanePath is the one-field projection, for a caller holding a
	// member's session (Production / Trial).
	licenseMemberPlanePath = "/v1/license/plane/member"
	// licensePlaneStateFilename is where the last known gate survives a restart,
	// beside the sync-health file the rail framework already writes.
	licensePlaneStateFilename = "license-plane.json"
)

// maxLicensePlaneBody caps the response read. The projection is a few dozen
// bytes; anything larger means we are not talking to this endpoint, and reading
// it unbounded would let a misrouted response consume memory.
const maxLicensePlaneBody = 16 << 10

var licensePlaneHTTPClient = httpx.NewSwappableDirect(10 * time.Second)

// licensePlaneWire is the slice of the projection this rail reads.
//
// 🔴 Deliberately NOT the whole projection, even for the Cluster path where the
// whole thing is available. Deserialising `state` would put the license state
// machine's vocabulary inside the proxy, and the next person to touch this file
// would find it sitting there looking usable. The data path gets one word.
type licensePlaneWire struct {
	Forwarding string `json:"forwarding"`
}

// licensePlaneRail declares the rail.
//
// Gate: the cache exists. 🔴 Note what is NOT gated — there is no edition check.
// Personal has no control URL, so the framework skips the cycle without counting
// a failure and the cache stays never-synced, which allows forwarding. That is
// the requirement expressed structurally rather than by branching.
func (s *Supervisor) licensePlaneRail() railSpec {
	return railSpec{
		name:     "license_plane",
		interval: licensePlanePollInterval,
		// A cluster worker has no team JWT and never will; it authenticates with
		// the node's control service token inside sync instead. Same split as
		// fallbackPolicyRail, and for the same reason.
		needsTeamJWT: !s.isClusterNode(),
		// 🔴 The gate requires a control URL, and that is not redundant with the
		// framework's own check.
		//
		// railset.go treats a missing control URL as a FAILED cycle ("a team rail
		// with local work but no control URL is a real broken state"), which is the
		// right reading for a rail that only exists on team installs. This one runs
		// everywhere: Personal has no control plane by design, so without this the
		// rail would count a failure every 60s and settle into a permanently STALE
		// then OFFLINE entry in /status on every Personal machine — a red signal
		// that means "this edition has no license", which is not a fault.
		//
		// 🚫 Nothing is lost on a team install whose control URL really was wiped:
		// the cache keeps its last known gate, its age keeps growing in /status,
		// and proxy.LicensePlaneStaleCeiling denies after seven days regardless of
		// whether the rail was counting failures on the way there.
		//
		// (Verified live 2026-08-27 on an isolated Personal proxy, which showed
		// this rail at fails=1 and climbing before this gate existed.)
		gate: func(_ *generation) bool {
			return s.licensePlane != nil && readControlPanelURL() != ""
		},
		hydrate: s.hydrateLicensePlane,
		sync:    s.syncLicensePlane,
	}
}

// LicensePlaneCache exposes the gate cache for the health surface and for the
// request path's wiring. nil on a build where the capability is not wired, which
// /status reports honestly by saying never_synced rather than by inventing one.
func (s *Supervisor) LicensePlaneCache() *proxy.LicensePlaneCache { return s.licensePlane }

// syncLicensePlane performs one pull.
//
// 🔴 A failed cycle NEVER changes the gate. keep-last-known is the whole posture
// here: a control-plane blip must not stop a licensed deployment's traffic, and
// it must not resurrect a denied one either. The staleness ceiling in
// proxy.LicensePlaneStaleCeiling is what stops "keep last known" from becoming
// "forward for ever after unplugging the control plane".
func (s *Supervisor) syncLicensePlane(ctx context.Context, _ *generation, masterURL, bearer string) error {
	cache := s.licensePlane
	if cache == nil {
		return nil
	}

	url := masterURL + licenseMemberPlanePath
	if s.isClusterNode() {
		controlToken := s.clusterControlServiceToken()
		if controlToken == "" {
			// 🔴 Not an error, and not a denial. A node that has not been given a
			// control credential yet is still provisioning; counting it as a failure
			// would report a broken rail on a healthy worker, and denying would stop
			// a deployment that has done nothing wrong. It keeps the last known gate
			// and the next cycle retries.
			return nil
		}
		// 🔴 The CONTROL token, not Cluster.ServiceToken — that one is the hub's,
		// and the control plane answers it 401. Same trap as syncFallbackPolicy.
		url = masterURL + licensePlanePath
		bearer = controlToken
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("build license-plane request: %w", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := licensePlaneHTTPClient.Get().Do(req)
	if err != nil {
		return fmt.Errorf("fetch license plane: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		// 🔴 404 means this control plane has no licensing surface at all, which
		// design D9 makes the CORRECT answer for Personal — the routes are absent
		// rather than answering "not applicable". It is a successful cycle that
		// establishes there is no gate, so it must not deny and must not be
		// counted as a failure.
		//
		// 🚫 It is NOT treated as proof of Personal, and nothing is stored on the
		// strength of it. An OLD Production or Cluster build answers 404 here too
		// — aikey-cli was caught making exactly that inference and reporting real
		// team deployments as "Personal edition" (see
		// aikey-cli/src/license_identity.rs). Leaving the cache untouched is right
		// for both readings: Personal stays never-synced and forwards, while an old
		// build keeps whatever it already knew.
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("license plane: HTTP %d", resp.StatusCode)
	}

	var wire licensePlaneWire
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxLicensePlaneBody)).Decode(&wire); err != nil {
		return fmt.Errorf("decode license plane: %w", err)
	}

	// 🔴 An unrecognized gate is a FAILED cycle, not a guess.
	//
	// Mapping an unknown value to `allow` would silently disable the gate the
	// first time the wire format moved; mapping it to `deny` would stop a paying
	// fleet on the same event. Refusing makes the rail go STALE and then OFFLINE
	// in /status — loud, and the cache keeps its last known answer meanwhile, so
	// the staleness ceiling still applies. This is also what lets the cache assume
	// it only ever holds one of two values.
	if wire.Forwarding != licenseGateAllow && wire.Forwarding != licenseGateDeny {
		slog.Warn("license plane returned a forwarding value this build does not recognize; keeping the last known gate",
			"event.name", observability.EventProxyLicensePlaneUnreadable,
			"forwarding", wire.Forwarding, "url", url)
		return fmt.Errorf("license plane: unrecognized forwarding value %q", wire.Forwarding)
	}

	before, _, hadBefore := cache.Snapshot()
	cache.Observe(wire.Forwarding, time.Now())

	if !hadBefore || before != wire.Forwarding {
		// 🔴 Logged on the TRANSITION only. A per-cycle line would write once a
		// minute for ever, and a per-REQUEST line on a denied deployment is how a
		// developer machine once accumulated a 466 MB log.
		slog.Warn("the deployment's license forwarding gate changed",
			"event.name", observability.EventProxyLicensePlaneChanged,
			"from", before, "to", wire.Forwarding)
	}
	s.persistLicensePlane()
	return nil
}

// The gate values, restated for the rail's validation. They must agree with
// internal/proxy's copy; that package holds the authoritative comment about why
// this contract is written out twice rather than imported.
const (
	licenseGateAllow = "allow"
	licenseGateDeny  = "deny"
)

// licensePlaneStateFile is the persisted last-known gate.
type licensePlaneStateFile struct {
	Forwarding string `json:"forwarding"`
	// ObservedAt is unix millis of the poll that produced it.
	ObservedAt int64 `json:"observed_at"`
	WrittenAt  int64 `json:"written_at"`
}

func licensePlaneStatePath() (string, error) {
	if dir := os.Getenv("AIKEY_RUN_DIR"); dir != "" {
		return filepath.Join(dir, licensePlaneStateFilename), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aikey", "run", licensePlaneStateFilename), nil
}

// hydrateLicensePlane preloads the gate a previous process learned.
//
// 🔴 Without this the staleness ceiling is worth very little: `deny` would live
// only in memory, and restarting the proxy — which any user may do, and which a
// crash does for them — would return the cache to never-synced and forward
// again. A gate a restart clears is not a gate.
//
// Best-effort in the "enhancing, never depended upon" sense: a missing or
// unreadable file leaves the cache never-synced, which ALLOWS. The rail's first
// cycle runs immediately after this (railset.go: hydrate, then cycle, then the
// ticker), so a healthy deployment replaces whatever this did within one round
// trip rather than one poll interval.
func (s *Supervisor) hydrateLicensePlane(_ *generation) {
	if s.licensePlane == nil {
		return
	}
	path, err := licensePlaneStatePath()
	if err != nil {
		return
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path is derived from the run dir, not from input
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("the last known license gate could not be read; this proxy starts without one",
				"event.name", observability.EventProxyLicensePlaneFileFailed, "error", err.Error())
		}
		return
	}
	var st licensePlaneStateFile
	if err := json.Unmarshal(raw, &st); err != nil {
		slog.Warn("the last known license gate file is unreadable; this proxy starts without one",
			"event.name", observability.EventProxyLicensePlaneFileFailed, "error", err.Error())
		return
	}
	if st.ObservedAt <= 0 || (st.Forwarding != licenseGateAllow && st.Forwarding != licenseGateDeny) {
		slog.Warn("the last known license gate file holds no usable value; this proxy starts without one",
			"event.name", observability.EventProxyLicensePlaneFileFailed, "forwarding", st.Forwarding)
		return
	}
	s.licensePlane.Hydrate(st.Forwarding, time.UnixMilli(st.ObservedAt))
}

// persistLicensePlane writes the current gate so it survives a restart.
//
// Best-effort with a WARN: a write failure must not fail the sync cycle, because
// the gate in memory is already correct and refusing the cycle would make a disk
// problem look like a control-plane problem.
func (s *Supervisor) persistLicensePlane() {
	forwarding, observedAt, ok := s.licensePlane.Snapshot()
	if !ok {
		return
	}
	path, err := licensePlaneStatePath()
	if err != nil {
		return
	}
	err = func() error {
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
			return mkErr
		}
		data, mErr := json.Marshal(licensePlaneStateFile{
			Forwarding: forwarding,
			ObservedAt: observedAt.UnixMilli(),
			WrittenAt:  time.Now().UnixMilli(),
		})
		if mErr != nil {
			return mErr
		}
		tmp := path + ".tmp"
		if wErr := os.WriteFile(tmp, data, 0o600); wErr != nil {
			return wErr
		}
		return os.Rename(tmp, path)
	}()
	if err != nil {
		slog.Warn("the license gate state file could not be written; a restart will start without a last known gate",
			"event.name", observability.EventProxyLicensePlaneFileFailed, "error", err.Error())
	}
}
