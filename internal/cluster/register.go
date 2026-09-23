// Package cluster implements aikey-proxy's cluster-node behavior (V3c): a node
// registers with — and heartbeats to — the aikey-hub name service so clients can
// discover it via /cluster/resolve. Entirely inert unless cluster mode is on
// (the supervisor only starts the Registrar when config.Cluster.Enabled), so the
// local Personal/Trial proxy is unaffected.
package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
)

const defaultHeartbeatInterval = 5 * time.Second

// CapabilityDeviceRoutingToken is advertised by every build that knows how to
// serve device-routing-token traffic (the strict branch: use the account the
// control plane named in the internal header, never pick another one).
//
// spec: R-device-routing-token-dispatch-20 节点能力闸 —— 节点随注册 / 心跳上报本
// 程序支持的能力，控制面核对后才把该类流量交给它；缺能力 → 503，不转发也不改选
// 节点。roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/device-routing-token-dispatch/spec.md
//
// 🔴 The advertising condition is "THIS BINARY supports it" and nothing else —
// deliberately NOT "the node vault has a route_kind column". A column survives a
// daemon downgrade while the downgraded daemon stops writing the value, so the
// column would vouch for a node that cannot actually honor the routing (评审
// 2026-09-21 第二轮 #1). The daemon side is caught per-request by the worker's
// own route_kind self-check instead (counters below).
const CapabilityDeviceRoutingToken = "device_routing_token"

// nodeCapabilities lists what this proxy build can serve. Additive by design:
// the hub keeps whatever it does not recognize, and an old hub ignores the
// whole list.
func nodeCapabilities() []string {
	return []string{CapabilityDeviceRoutingToken}
}

// DeviceRoutingTokenStats are the worker's device-routing self-check counters,
// reported under the `device_routing_token` object of the health payload:
//
//   - RouteKindMissingActive — tokens that STILL do not line up right now
//     (internal header present, local route kind is not device_routing_token).
//     Alerting reads only this one, so a repaired route clears the CRIT with no
//     proxy restart.
//   - RouteKindMissingTotal — lifetime count, diagnosis only, never alerting.
//
// Field names are the health-signal contract's dotted names verbatim
// (design §4b.5): device_routing_token.route_kind_missing_active / _total.
type DeviceRoutingTokenStats struct {
	RouteKindMissingActive int64 `json:"route_kind_missing_active"`
	RouteKindMissingTotal  int64 `json:"route_kind_missing_total"`
}

// errUnknownNode is returned by heartbeat when the hub replies 409 (it lost this
// node, e.g. after a hub restart) — the caller re-registers.
var errUnknownNode = fmt.Errorf("hub does not know this node")

// Registrar keeps this proxy node registered + alive in ONE hub name service.
// The supervisor runs an independent Registrar per configured hub
// (cluster.hub_urls); nothing here is shared between instances.
type Registrar struct {
	client *httpx.SwappableClient // control-plane→hub: rebuilt on host network change (self-heal registry)
	// healthFn, when set, supplies the optional `health` heartbeat field
	// (P0-B): node-local health (daemon sync status + proxy metrics) rides
	// the existing heartbeat so it becomes externally visible with zero new
	// ports/auth. nil ⇒ bare heartbeat (old wire shape, hub accepts both).
	healthFn func() map[string]any
	// deviceRoutingStatsFn supplies the device_routing_token counters. nil ⇒
	// zeros, which is the honest answer for a build whose self-check has not
	// landed yet: the capability is about what this binary CAN serve, the
	// counters are about what it has seen go wrong.
	deviceRoutingStatsFn func() DeviceRoutingTokenStats
	hubURL               string
	nodeID               string
	nodeAddr             string
	internalAddr         string // cluster-internal dial address (optional; see config.ClusterConfig.InternalAddr)
	serviceToken         string // R1: Bearer token for the hub's gated /cluster/* endpoints
	weight               int
	interval             time.Duration // adopted from the hub's register response
}

// NewRegistrar builds a Registrar. weight < 1 is normalized to 1. serviceToken
// authenticates to the hub (R1); empty only for an unauthenticated dev hub.
func NewRegistrar(hubURL, nodeID, nodeAddr string, weight int, serviceToken string) *Registrar {
	if weight < 1 {
		weight = 1
	}
	return &Registrar{
		hubURL:       strings.TrimRight(hubURL, "/"),
		nodeID:       nodeID,
		nodeAddr:     nodeAddr,
		weight:       weight,
		serviceToken: serviceToken,
		client:       httpx.NewSwappableDirect(5 * time.Second),
		interval:     defaultHeartbeatInterval,
	}
}

// WithInternalAddr sets the cluster-internal address registered alongside the
// public node address. Empty leaves the register payload unchanged, so a fleet
// without the setting is wire-identical to before the field existed.
func (r *Registrar) WithInternalAddr(addr string) *Registrar {
	r.internalAddr = strings.TrimSpace(addr)
	return r
}

// SetHealthSource installs the health collector (see Registrar.healthFn).
// Call before Run; the collector runs once per heartbeat/register.
func (r *Registrar) SetHealthSource(fn func() map[string]any) { r.healthFn = fn }

// SetDeviceRoutingTokenStatsSource installs the counter provider (see
// Registrar.deviceRoutingStatsFn). Call before Run; it runs once per
// heartbeat/register, like the health collector.
func (r *Registrar) SetDeviceRoutingTokenStatsSource(fn func() DeviceRoutingTokenStats) {
	r.deviceRoutingStatsFn = fn
}

// deviceRoutingTokenStats reads the counters, defaulting to zeros.
func (r *Registrar) deviceRoutingTokenStats() DeviceRoutingTokenStats {
	if r.deviceRoutingStatsFn == nil {
		return DeviceRoutingTokenStats{}
	}
	return r.deviceRoutingStatsFn()
}

// withHealth adds the optional `health` field to a heartbeat/register payload.
// The collector is transparent transport: the Registrar never interprets the
// content, so daemon-side schema evolution needs no proxy change.
//
// The capability list and the device_routing_token counters are added by the
// Registrar itself, not by the collector: they describe the BINARY, and the
// collector's job is to forward what other components said about themselves.
//
// 🔴 They ride INSIDE the health section rather than beside it, so a registrar
// with no health collector still sends the legacy bare payload — mixed-version
// fleets (and TestHeartbeatCarriesHealth) depend on that shape. Cluster mode
// always installs the collector, and the collector always returns at least a
// `proxy` section, so a real cluster node always advertises: see
// internal/supervisor/supervisor.go:781 and health.go's NodeHealthSource.
func (r *Registrar) withHealth(payload map[string]any) map[string]any {
	if r.healthFn != nil {
		if h := r.healthFn(); len(h) > 0 {
			// spec: R-device-routing-token-dispatch-20 节点能力闸（上报侧）
			h["capabilities"] = nodeCapabilities()
			// 🔴 Reusing CapabilityDeviceRoutingToken ("device_routing_token") as the
			// health-object KEY here, not just as a capabilities[] list entry above, is
			// deliberate: hub's capabilityHealth struct (aikey-hub/nameservice/internal/
			// api/server.go, task 4.14) decodes this same sub-object via the JSON tag
			// `json:"device_routing_token"` into NodeCapabilityReport's
			// RouteKindMissing* counters. One literal serves two independent contracts
			// (list membership vs. map/JSON key) that happen to share a name because
			// they describe the same capability. register_capability_test.go pins the
			// literal string rather than this constant, so renaming the constant alone
			// would not silently drift the wire key — that test reads
			// health["device_routing_token"] directly and would catch the mismatch.
			h[CapabilityDeviceRoutingToken] = r.deviceRoutingTokenStats()
			payload["health"] = h
		}
	}
	return payload
}

// register POSTs /cluster/register and adopts the hub's heartbeat interval.
func (r *Registrar) register(ctx context.Context) error {
	payload := map[string]any{
		"node_id": r.nodeID,
		"addr":    r.nodeAddr,
		"weight":  r.weight,
	}
	if r.internalAddr != "" {
		payload["internal_addr"] = r.internalAddr
	}
	body, _ := json.Marshal(r.withHealth(payload))
	resp, err := r.post(ctx, "/cluster/register", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register: hub returned %d", resp.StatusCode)
	}
	var out struct {
		HeartbeatIntervalSeconds int `json:"heartbeat_interval_seconds"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) == nil && out.HeartbeatIntervalSeconds > 0 {
		r.interval = time.Duration(out.HeartbeatIntervalSeconds) * time.Second
	}
	return nil
}

// heartbeat POSTs /cluster/heartbeat; returns errUnknownNode on 409.
func (r *Registrar) heartbeat(ctx context.Context) error {
	body, _ := json.Marshal(r.withHealth(map[string]any{"node_id": r.nodeID}))
	resp, err := r.post(ctx, "/cluster/heartbeat", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusConflict:
		return errUnknownNode
	default:
		return fmt.Errorf("heartbeat: hub returned %d", resp.StatusCode)
	}
}

func (r *Registrar) post(ctx context.Context, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.hubURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.serviceToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.serviceToken)
	}
	return r.client.Get().Do(req)
}

// Run registers, then heartbeats on the hub-provided interval until ctx is done.
// On 409 (or a heartbeat failure that may mean the hub restarted) it re-registers.
// Failures are logged and retried — a transient hub outage never kills the proxy.
//
// One Run per hub: the supervisor starts an independent Registrar for every
// configured hub, each in its own goroutine. Run keeps no state outside its
// receiver, so a hub that hangs or refuses connections can only stall its own
// loop. Every log line carries the hub URL so an operator can tell WHICH hub is
// failing (fenced by TestRegistrar_EveryLogLineCarriesHubLabel).
// Why: multi-hub fan-out registration so every hub's node table is identical
// (update: roadmap20260320/技术实现/update/20260922-集群入口高可用-hub多实例与两台入口机.md, DEC-cluster-ingress-ha-2).
func (r *Registrar) Run(ctx context.Context) {
	if err := r.register(ctx); err != nil {
		slog.Warn("cluster: initial register failed; will retry on next tick", "error", err, "hub", r.hubURL)
	} else {
		slog.Info("cluster: registered with hub", "node_id", r.nodeID, "hub", r.hubURL)
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			switch err := r.heartbeat(ctx); {
			case errors.Is(err, errUnknownNode):
				slog.Warn("cluster: hub lost this node; re-registering", "hub", r.hubURL)
				if rerr := r.register(ctx); rerr != nil {
					slog.Warn("cluster: re-register failed", "error", rerr, "hub", r.hubURL)
				}
			case err != nil:
				slog.Warn("cluster: heartbeat failed; attempting re-register", "error", err, "hub", r.hubURL)
				_ = r.register(ctx)
			}
		}
	}
}
