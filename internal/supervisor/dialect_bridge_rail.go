package supervisor

// dialect_bridge_rail.go — the control plane's half of the Chat Completions ⇄
// Responses bridge switch.
//
// # What problem this solves
//
// Until now the bridge could only be switched on by editing aikey-user.yaml on
// every worker and restarting the proxy. The control plane could neither show
// the value nor change it, so "is the bridge on in this deployment?" could only
// be answered by logging into each machine in turn.
//
// This rail pulls the deployment's answer and applies it to the LIVE proxy — no
// restart, no config file write, no reload.
//
// # 🔴 Three states, and the third one is why this file is careful
//
// The policy endpoint OMITS `enabled` while no administrator has ever answered.
// An absent field means "the control plane has no opinion", and this rail then
// leaves the local config in charge. That is not a nicety: deployments that
// turned the bridge on in their own aikey-user.yaml (staging has two such
// workers) stay on across this upgrade precisely because absence is not false.
//
// # Why a rail and not a hand-written poll
//
// 2026-07-03: two hand-written pollers baked their control URL at goroutine
// start and starved silently for 7+ hours. The SyncRail framework re-evaluates
// gate, credential and control URL every cycle and makes failure visible in
// /status. See railset.go.
//
// Design: roadmap20260320/技术实现/update/
//
//	20260912-ChatCompletions桥接开关-控制面下发-技术方案.md

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
)

// dialectBridgePollInterval matches the other governance rails. One number for
// an operator to remember: "a switch in the console reaches the fleet within a
// minute", the same promise compliance and conversation-audit already make.
const dialectBridgePollInterval = 60 * time.Second

const (
	// dialectBridgePolicyPath is for a caller holding the deployment's control
	// service token — i.e. a Cluster node.
	dialectBridgePolicyPath = "/v1/dialect-bridge/policy"
	// dialectBridgeMemberPolicyPath is the same answer for a proxy running on an
	// employee's machine, which has a team JWT and nothing else. Production and
	// Trial forward through those, so without this path the switch would be
	// enforceable on one edition out of three.
	dialectBridgeMemberPolicyPath = "/v1/dialect-bridge/policy/member"
	// dialectBridgeMasterPolicyKey holds the last known answer so a restart does
	// not fall back to the local file for a minute — which, on a deployment that
	// had switched the bridge OFF centrally while its config file still said on,
	// would turn it back on for that minute.
	dialectBridgeMasterPolicyKey = "chat_completions_bridge.master_policy"
)

// maxDialectBridgeBody caps the response read. The document is a few dozen
// bytes; anything larger means we are not talking to this endpoint.
const maxDialectBridgeBody = 16 << 10

var dialectBridgeHTTPClient = httpx.NewSwappableDirect(10 * time.Second)

// dialectBridgeWire is the policy document.
//
// 🔴 *bool, not bool. Absent and false are different answers — "nobody has
// decided" versus "the deployment says off" — and a plain bool would silently
// turn the first into the second at decode time, which is the failure this whole
// design exists to avoid.
type dialectBridgeWire struct {
	Enabled *bool `json:"enabled"`
}

func (s *Supervisor) dialectBridgeRail() railSpec {
	return railSpec{
		name:     "dialect_bridge",
		interval: dialectBridgePollInterval,
		// A cluster worker has no team JWT and never will; it authenticates with
		// the node's control service token inside sync instead. Same split as
		// licensePlaneRail and fallbackPolicyRail.
		needsTeamJWT: !s.isClusterNode(),
		// A deployment with no control plane (Personal) is idle here, not broken:
		// the local config file is the only answer there is, and counting a
		// failure every 60s would paint a red rail on a healthy machine. Same
		// reasoning as licensePlaneRail's gate.
		gate:    func(_ *generation) bool { return readControlPanelURL() != "" },
		hydrate: s.hydrateDialectBridge,
		sync:    s.syncDialectBridge,
	}
}

// hydrateDialectBridge preloads the last known answer from the vault so the
// window between start-up and the first successful poll is not served with the
// local file's value. Best-effort: a missing or unreadable key just means "not
// known yet", which is exactly the state a fresh install is in.
func (s *Supervisor) hydrateDialectBridge(_ *generation) {
	if s.cfg == nil {
		return
	}
	if s.cfg.Vault.Path == "" {
		return
	}
	raw, err := vault.ReadConfigString(s.cfg.Vault.Path, dialectBridgeMasterPolicyKey)
	if err != nil || raw == "" {
		return
	}
	var wire dialectBridgeWire
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		slog.Warn("the persisted dialect-bridge policy could not be parsed; falling back to local configuration until the next poll",
			"event.name", observability.EventProxyDialectBridgePolicyUnreadable,
			"error", err)
		return
	}
	if wire.Enabled != nil {
		s.masterBridge.Store(wire.Enabled)
	}
}

// syncDialectBridge performs one pull and applies the answer to the live proxy.
//
// 🔴 A failed cycle NEVER changes the switch. Keep-last-known is the posture
// here, and the failure direction is the OPPOSITE of the compliance rail's on
// purpose: there, an unreachable control plane must collect LESS, so it settles
// to off. Here, settling to off would cut clients off mid-conversation, and the
// switch is not a security boundary — the upstream allowlist is, and that never
// leaves local configuration.
func (s *Supervisor) syncDialectBridge(ctx context.Context, gen *generation, masterURL, bearer string) error {
	url := masterURL + dialectBridgeMemberPolicyPath
	if s.isClusterNode() {
		controlToken := s.clusterControlServiceToken()
		if controlToken == "" {
			// A node that has not been given a control credential yet is still
			// provisioning. Not an error, and not a reason to change the switch.
			return nil
		}
		// 🔴 The CONTROL token, not Cluster.ServiceToken — that one is the hub's,
		// and the control plane answers it 401. Same trap as syncFallbackPolicy.
		url = masterURL + dialectBridgePolicyPath
		bearer = controlToken
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("build dialect-bridge policy request: %w", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := dialectBridgeHTTPClient.Get().Do(req)
	if err != nil {
		return fmt.Errorf("fetch dialect-bridge policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		// 🔴 This control plane predates the switch. That is a successful cycle
		// establishing there is no mandate — NOT a failure, or every deployment
		// that has not upgraded its control plane yet would show a red rail
		// forever. Nothing is stored: the local config keeps deciding, which is
		// exactly how those deployments behaved before this rail existed.
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dialect-bridge policy: HTTP %d", resp.StatusCode)
	}

	var wire dialectBridgeWire
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDialectBridgeBody)).Decode(&wire); err != nil {
		return fmt.Errorf("decode dialect-bridge policy: %w", err)
	}

	before := s.masterBridge.Load()
	s.masterBridge.Store(wire.Enabled)
	// No vault path means there is nothing to persist to — and writing anyway
	// creates a file named after the empty DSN's pragma string, which is how a
	// stray `?_pragma=busy_timeout(5000)` file appeared in this package during
	// development. Persistence is an enhancement here, never a dependency: a
	// worker that cannot save the answer still applies it.
	if s.cfg != nil && s.cfg.Vault.Path != "" {
		_ = vault.WriteConfigString(s.cfg.Vault.Path, dialectBridgeMasterPolicyKey, renderDialectBridgePolicy(wire.Enabled))
	}

	if bridgeAnswerChanged(before, wire.Enabled) {
		// Logged on the TRANSITION only: a per-cycle line would write once a
		// minute for ever.
		slog.Info("the deployment's dialect-bridge switch changed",
			"event.name", observability.EventProxyDialectBridgePolicyChanged,
			"from", describeBridgeAnswer(before),
			"to", describeBridgeAnswer(wire.Enabled),
			"effective", s.effectiveChatCompletionsBridgeEnabled())
		// Apply to the RUNNING proxy. No reload: the bridge runtime is an atomic
		// pointer the request path reads per request, so this takes effect on the
		// next request without dropping a connection.
		if gen != nil {
			s.applyChatCompletionsBridge(gen.proxy)
		}
	}
	return nil
}

// renderDialectBridgePolicy writes the three states out in the shape the wire
// uses, so what is persisted and what was received cannot drift apart.
func renderDialectBridgePolicy(enabled *bool) string {
	if enabled == nil {
		return `{"enabled":null}`
	}
	return fmt.Sprintf(`{"enabled":%t}`, *enabled)
}

func bridgeAnswerChanged(before, after *bool) bool {
	switch {
	case before == nil && after == nil:
		return false
	case before == nil || after == nil:
		return true
	default:
		return *before != *after
	}
}

func describeBridgeAnswer(v *bool) string {
	if v == nil {
		return "unset"
	}
	if *v {
		return "on"
	}
	return "off"
}

// effectiveChatCompletionsBridgeEnabled is the SINGLE place the two sources are
// reconciled.
//
// 🔴 Why it must stay single. The bridge switch is injected into the proxy when a
// generation is built, and a generation is rebuilt on every Reload — which the
// vault's 5s change_seq tick, a compliance policy change and a quota policy
// change can all trigger. If buildGeneration read the config file directly while
// this rail wrote the control plane's answer, then any unrelated reload would
// re-inject the local value and the switch would appear to flip back on its own,
// with nothing in any log. Both paths go through here instead.
//
// Precedence: the control plane wins when it has answered at all; otherwise the
// local file decides. See BridgeSwitchSource for how this is reported.
func (s *Supervisor) effectiveChatCompletionsBridgeEnabled() bool {
	if v := s.masterBridge.Load(); v != nil {
		return *v
	}
	if s.cfg != nil {
		return s.cfg.ChatCompletionsBridge.Enabled
	}
	return false
}

// chatCompletionsBridgeUpstreams converts the configured allowlist into the
// proxy's shape.
//
// 🔴 The allowlist is deliberately NOT part of the control-plane switch. An OAuth
// access token is not a key the customer can cheaply rotate — it IS the ChatGPT
// subscription, and any host that receives one holds the whole account — so which
// hosts may receive one stays in configuration that ships with the deployment and
// is reviewed with it. See the design doc §D5.
func (s *Supervisor) chatCompletionsBridgeUpstreams() []proxy.BridgeUpstreamRule {
	if s.cfg == nil {
		return nil
	}
	rules := make([]proxy.BridgeUpstreamRule, 0, len(s.cfg.ChatCompletionsBridge.Upstreams))
	for _, u := range s.cfg.ChatCompletionsBridge.Upstreams {
		rules = append(rules, proxy.BridgeUpstreamRule{Host: u.Host, Dialect: u.Dialect})
	}
	return rules
}

// applyChatCompletionsBridge injects the effective switch into a proxy. Called
// from buildGeneration (for a new generation) and from this rail (for the
// running one) — the two callers that must never disagree.
func (s *Supervisor) applyChatCompletionsBridge(p *proxy.Proxy) {
	if p == nil {
		return
	}
	p.SetChatCompletionsBridge(s.effectiveChatCompletionsBridgeEnabled(), s.chatCompletionsBridgeUpstreams())
}

// BridgeSwitchSource names where the effective value came from, for /status.
//
// Without this an operator who turns the switch on in the console and sees no
// change has no way to tell "the control plane's answer has not arrived" from
// "this worker is following its local file" — which was the whole complaint
// about the hand-edited YAML, reproduced one layer up.
func (s *Supervisor) BridgeSwitchSource() string {
	if s.masterBridge.Load() != nil {
		return "control_plane"
	}
	return "local_config"
}

// ChatCompletionsBridgeEnabled reports the effective switch for /status.
func (s *Supervisor) ChatCompletionsBridgeEnabled() bool {
	return s.effectiveChatCompletionsBridgeEnabled()
}
