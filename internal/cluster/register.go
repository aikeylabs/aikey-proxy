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
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const defaultHeartbeatInterval = 5 * time.Second

// errUnknownNode is returned by heartbeat when the hub replies 409 (it lost this
// node, e.g. after a hub restart) — the caller re-registers.
var errUnknownNode = fmt.Errorf("hub does not know this node")

// Registrar keeps this proxy node registered + alive in the hub name service.
type Registrar struct {
	hubURL       string
	nodeID       string
	nodeAddr     string
	weight       int
	serviceToken string // R1: Bearer token for the hub's gated /cluster/* endpoints
	client       *http.Client
	interval     time.Duration // adopted from the hub's register response

	// healthFn, when set, supplies the optional `health` heartbeat field
	// (P0-B): node-local health (daemon sync status + proxy metrics) rides
	// the existing heartbeat so it becomes externally visible with zero new
	// ports/auth. nil ⇒ bare heartbeat (old wire shape, hub accepts both).
	healthFn func() map[string]any
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
		client:       &http.Client{Timeout: 5 * time.Second},
		interval:     defaultHeartbeatInterval,
	}
}

// SetHealthSource installs the health collector (see Registrar.healthFn).
// Call before Run; the collector runs once per heartbeat/register.
func (r *Registrar) SetHealthSource(fn func() map[string]any) { r.healthFn = fn }

// withHealth adds the optional `health` field to a heartbeat/register payload.
// The collector is transparent transport: the Registrar never interprets the
// content, so daemon-side schema evolution needs no proxy change.
func (r *Registrar) withHealth(payload map[string]any) map[string]any {
	if r.healthFn != nil {
		if h := r.healthFn(); len(h) > 0 {
			payload["health"] = h
		}
	}
	return payload
}

// register POSTs /cluster/register and adopts the hub's heartbeat interval.
func (r *Registrar) register(ctx context.Context) error {
	body, _ := json.Marshal(r.withHealth(map[string]any{
		"node_id": r.nodeID,
		"addr":    r.nodeAddr,
		"weight":  r.weight,
	}))
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
	return r.client.Do(req)
}

// Run registers, then heartbeats on the hub-provided interval until ctx is done.
// On 409 (or a heartbeat failure that may mean the hub restarted) it re-registers.
// Failures are logged and retried — a transient hub outage never kills the proxy.
func (r *Registrar) Run(ctx context.Context) {
	if err := r.register(ctx); err != nil {
		slog.Warn("cluster: initial register failed; will retry on next tick", "error", err)
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
			case err == errUnknownNode:
				slog.Warn("cluster: hub lost this node; re-registering")
				if rerr := r.register(ctx); rerr != nil {
					slog.Warn("cluster: re-register failed", "error", rerr)
				}
			case err != nil:
				slog.Warn("cluster: heartbeat failed; attempting re-register", "error", err)
				_ = r.register(ctx)
			}
		}
	}
}
