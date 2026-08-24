package events

import (
	"context"
	"fmt"
	"net/http"
)

// authorize attaches the collector Authorization header, and is the ONE place
// that decides how a collector-bound request proves who it is.
//
// 🔴 WHY THIS EXISTS (2026-08-24). The usage pipeline had TWO implementations of
// this decision and only one of them worked. Uploads resolved a credential
// correctly (content_reporter.go). The RECONCILE path — the idempotent read that
// tells the reporter which sequence numbers the collector already holds — built
// its requests with no Authorization at all, so every call answered 401.
//
// Measured on a Windows box: `usage.reporter.auto_reconcile_failed`, every ~35
// seconds, `GET .../v1/diagnostics/completeness: status 401`, while the panel
// showed zero usage. The server was right to refuse; the client never asked.
//
// This project's own rule is "event-driven writes must be paired with an
// idempotent reconcile read". That read had never once succeeded on an
// authenticated deployment — the pairing existed in the design and in the code
// shape, but not in the wire. A shared helper is the fix that keeps it true:
// there is now one function to get wrong, and both callers use it.
//
// An empty credential is legitimate (network-trust deployments send no header),
// so nil/empty is silence, not an error. A credential that FAILS to produce a
// bearer is an error — that is a broken login, not a trust decision.
func authorize(ctx context.Context, req *http.Request, cred Credential) error {
	if cred == nil {
		return nil
	}
	tok, err := cred.Bearer(ctx)
	if err != nil {
		return fmt.Errorf("credential bearer: %w", err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return nil
}
