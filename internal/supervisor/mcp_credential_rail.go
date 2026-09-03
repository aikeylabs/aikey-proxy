// mcp_credential_rail.go — P4 task 4.5: the rail that carries MCP backend
// credential material from the control plane to this proxy.
//
// # What problem this closes
//
// Without it, a hosted MCP backend can be configured perfectly and can never
// authenticate: the policy rail carries the backend's credential_id but
// deliberately carries no material (PolicyBackend has nowhere to put a secret,
// and the policy poll is unauthenticated). This rail is the authenticated half.
//
// # 🔴 Why it is a SEPARATE rail, not a field on the policy
//
// GET /v1/mcp/policy is unauthenticated by design — it is a topology document
// polled by every node, and it takes its organisation from a query parameter.
// That shape is survivable for topology and is not survivable for secrets.
// This rail instead uses the account credential the framework already resolves,
// and the control plane derives the organisation from the caller's own seats
// (GET /accounts/me/mcp-credentials). Same principle as the LLM key material
// rail, GET /accounts/me/group-runtime.
//
// # The failure posture, and why it is not the same as the policy rail's
//
// The policy rail keeps serving a stale policy when the control plane is
// unreachable, because losing it would disconnect every Agent in the fleet.
// This rail keeps its last-known material for the same reason — a laptop is
// offline routinely, and blanking credentials on one failed poll would turn a
// switch reboot into a tool outage.
//
// 🔴 But the two have different BOUNDS. A stale grant is a stale opinion; a
// stale secret is material that may have been revoked. So the on-disk copy
// expires (mcp.CredentialStore.maxAge) where the policy cache's does not need
// to be as strict, and a REVOKED credential disappears from the delivered set,
// which Replace applies by replacing rather than merging.

package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/mcp"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// mcpCredentialPollInterval matches the policy rail's 60s.
//
// 🔴 Same number on purpose: a revocation is applied by BOTH rails (the policy
// drops the binding, this one drops the material), and two intervals would mean
// a window in which the proxy holds a secret for a backend it no longer serves.
// The window would be short and it would be real.
const mcpCredentialPollInterval = 60 * time.Second

// mcpCredentialClient is separate from mcpHTTPClient so a hung credential poll
// cannot occupy the policy poll's connection pool — the policy rail is the one
// that must keep working when everything else is degraded.
var mcpCredentialClient = httpx.NewSwappableDirect(10 * time.Second)

// mcpCredentialRail declares the follower.
func (s *Supervisor) mcpCredentialRail() railSpec {
	return railSpec{
		name:     "mcp_credentials",
		interval: mcpCredentialPollInterval,
		// The material is account-scoped, so this rail needs the account
		// credential — exactly like group_runtime.
		needsTeamJWT: true,
		gate: func(_ *generation) bool {
			// 🔴 Gated on the STORE existing, not on "are there backends with
			// credentials". A gate that inspected the policy would go idle
			// exactly when the policy was missing, which is when a fresh proxy
			// most needs to fetch its material — and "idle" is not counted as a
			// failure, so the rail would look healthy while delivering nothing.
			return s.mcpCredentials != nil
		},
		hydrate: func(_ *generation) {
			if s.mcpCredentials == nil {
				return
			}
			// 🔴 Before the first poll, so a proxy that starts while the control
			// plane is down can still authenticate to backends it was already
			// using. The restore does NOT count as a successful poll.
			if n := s.mcpCredentials.RestoreFromCache(context.Background()); n > 0 {
				slog.Info("MCP backend credentials restored from the sealed local cache; "+
					"serving them until the first live delivery",
					"event.name", observability.EventProxyMCPCredentialsDelivered,
					"credentials", n, "source", "cache")
			}
		},
		sync: s.syncMCPCredentials,
	}
}

// syncMCPCredentials pulls one delivery and replaces the in-memory set.
//
// 🔴 Returns an error on every failure path WITHOUT touching the store. The
// framework counts it and surfaces it in /status; the last-known material stays
// in force. There is deliberately no path here that clears the store on a
// failed poll — see the file header.
func (s *Supervisor) syncMCPCredentials(ctx context.Context, _ *generation, masterURL, bearer string) error {
	store := s.mcpCredentials
	if store == nil {
		return nil
	}
	if masterURL == "" {
		return nil // no control plane on this node; not an error.
	}
	materials, err := fetchMCPCredentials(ctx, masterURL, bearer)
	if err != nil {
		slog.Warn("MCP credential delivery failed; keeping the material this proxy already holds",
			"event.name", observability.EventProxyMCPCredentialPollFailed,
			"held", store.Count(), "error", err.Error())
		return err
	}
	before := store.Count()
	store.Replace(ctx, materials)
	// 🔴 Logged only when the COUNT moves. A per-minute INFO line for a stable
	// set is how a log stops being read — and this is the line an operator
	// greps for when a tool starts failing.
	if len(materials) != before {
		slog.Info("MCP backend credentials delivered",
			"event.name", observability.EventProxyMCPCredentialsDelivered,
			"credentials", len(materials), "previously", before, "source", "control_plane")
	}
	return nil
}

// fetchMCPCredentials performs the authenticated GET.
//
// 🔴 The response body is never logged and never included in an error, at any
// level. It is a list of plaintext secrets, and an error string is the
// most-copied text in an incident.
func fetchMCPCredentials(ctx context.Context, masterURL, bearer string) ([]mcp.Material, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, masterURL+"/accounts/me/mcp-credentials", http.NoBody)
	if err != nil {
		return nil, err
	}
	if bearer == "" {
		// 🔴 Refused locally rather than sent. An unauthenticated request to
		// this endpoint is answered 401, and a 401 in the rail's last_error
		// would send an operator looking for a permissions problem when the
		// real state is "this node has no account credential yet".
		return nil, fmt.Errorf("no account credential available for the MCP credential rail")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := mcpCredentialClient.Get().Do(req)
	if err != nil {
		return nil, fmt.Errorf("mcp credential delivery unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		// An edition without an MCP control plane. Not an error, and not a
		// reason to hold onto material either — but clearing on a 404 would
		// misread a partially deployed upgrade, so this reports "nothing
		// delivered" and lets the caller keep what it has.
		return nil, fmt.Errorf("this control plane does not serve MCP credentials (404)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mcp credential delivery returned HTTP %d", resp.StatusCode)
	}
	// Bounded read: this body is small by construction (one entry per backend
	// credential), and an unbounded read from a compromised or confused control
	// plane is an easy way to exhaust a laptop's memory.
	const maxBody = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("reading mcp credential delivery: %w", err)
	}
	if len(raw) > maxBody {
		return nil, fmt.Errorf("mcp credential delivery exceeds the %d KiB ceiling", maxBody>>10)
	}
	var body struct {
		Credentials []mcp.Material `json:"credentials"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		// 🚫 The body is NOT included — it is a list of secrets.
		return nil, fmt.Errorf("mcp credential delivery is not the documented shape")
	}
	return body.Credentials, nil
}
