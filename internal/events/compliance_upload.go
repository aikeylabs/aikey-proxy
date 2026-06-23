package events

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// UploadComplianceEvents POSTs compliance event JSONs to the per-RouteSource
// compliance ingest endpoint (`<route>/v1/compliance/events`), reusing the SAME
// destination URL + credential as usage reporting — single source of truth (see
// update doc 20260603 §3). The proxy calls this for team-routed compliance
// events the detector handed back over the pipe; the credential/URL never leave
// the proxy, only the event JSON crosses the IPC boundary.
//
// Best-effort + bounded: a synchronous POST under the caller's ctx. Returns an
// error for the caller to log — a dropped compliance upload is an audit gap and
// must be visible (fail-loud, not silent).
func (r *Reporter) UploadComplianceEvents(ctx context.Context, routeSource string, eventJSONs [][]byte) error {
	if len(eventJSONs) == 0 {
		return nil
	}
	base := r.urlForRouteSource(routeSource)
	if base == "" {
		return fmt.Errorf("compliance upload: no route URL for source %q", routeSource)
	}
	url := strings.TrimRight(base, "/") + "/v1/compliance/events"

	var buf bytes.Buffer
	buf.WriteString(`{"events":[`)
	for i, e := range eventJSONs {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(e)
	}
	buf.WriteString(`]}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return fmt.Errorf("compliance upload: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cred := r.credentialForRouteSource(routeSource); cred != nil {
		bearer, bErr := cred.Bearer(ctx)
		if bErr != nil {
			return fmt.Errorf("compliance upload: credential for %q: %w", routeSource, bErr)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("compliance upload: POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("compliance upload: %s -> %d: %s", url, resp.StatusCode, string(body))
	}
	return nil
}
