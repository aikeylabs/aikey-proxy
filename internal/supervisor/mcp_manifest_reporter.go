package supervisor

// mcp_manifest_reporter.go — delivering a manifest observation to the control
// plane.
//
// 🔴 AUTHENTICATED. This is a WRITE rail: an unauthenticated report could
// fabricate a manifest and freeze an organisation's write tools. The control
// plane mounts POST /v1/mcp/manifest behind the same ingestAuth as
// POST /v1/compliance/events, so this sends the same credential the compliance
// uploader sends — the member JWT the proxy already maintains.
//
// 🚫 It deliberately does NOT invent its own token scheme. A second credential
// for a second rail is a second thing to rotate, and the one that gets forgotten
// is the one that expires at 3am.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/AiKeyLabs/aikey-proxy/internal/mcp"
)

// manifestReporter posts observations to the control plane.
//
// bearer is Supervisor.teamBearer — the SAME team account-JWT channel the
// group-login writeback and the usage reporter use. 🚫 No second token scheme:
// a second credential for a second rail is a second thing to rotate, and the one
// that gets forgotten is the one that expires at 3am.
type manifestReporter struct {
	masterURL string
	bearer    func(ctx context.Context) (string, error)
}

// Report implements mcp.ManifestReporter.
//
// 🔴 Returns an error rather than swallowing one. The syncer logs it at WARN and
// re-sends next round; making it silent here would mean drift detection could
// stop with nothing in the product saying so.
func (r *manifestReporter) Report(ctx context.Context, orgID string, m mcp.ObservedManifest) error {
	if r.masterURL == "" {
		return nil // no control plane; nothing to report to.
	}
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal observed manifest: %w", err)
	}
	u := r.masterURL + "/v1/mcp/manifest?org_id=" + url.QueryEscape(orgID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.bearer != nil {
		token, bErr := r.bearer(ctx)
		if bErr != nil {
			// 🔴 Refuse rather than send unauthenticated. An anonymous POST would
			// be rejected by the control plane anyway, and retrying it every five
			// minutes would fill the control plane's log with auth failures that
			// look like an attack.
			return fmt.Errorf("no credential for the manifest rail: %w", bErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := mcpHTTPClient.Get().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// 🔴 A 404 here is the "handler exists but was never routed" failure this
		// repo has shipped three times. Indistinguishable from unreachable at
		// this layer, which is why the real guard is the control plane's
		// route-registration fence.
		return fmt.Errorf("control plane answered HTTP %d", resp.StatusCode)
	}
	return nil
}
