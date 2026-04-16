package events

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// ReportableEvent contains all anchor fields required by collector-service.
// Built from request context after response completion.
type ReportableEvent struct {
	// identifiers
	EventID         string    `json:"event_id"`
	RequestID       string    `json:"request_id,omitempty"`
	TraceID         string    `json:"trace_id,omitempty"`
	ProxyInstanceID string    `json:"proxy_instance_id,omitempty"`
	DeviceID        string    `json:"device_id,omitempty"`

	// schema + source metadata
	SchemaVersion      int    `json:"schema_version"`
	SourceVersion      string `json:"source_version,omitempty"`
	ClientVersion      string `json:"client_version,omitempty"`
	ProxyConfigVersion string `json:"proxy_config_version,omitempty"`
	ProxyLoadedControlSeq *int64 `json:"proxy_loaded_control_seq,omitempty"`

	// timestamps (D4: event_time is local client time)
	EventTime  time.Time  `json:"event_time"`
	OccurredAt time.Time  `json:"occurred_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`

	// ownership (D3 naming)
	OrgID     string `json:"org_id"`
	AccountID string `json:"account_id,omitempty"`
	SeatID    string `json:"seat_id,omitempty"`

	// routing — audit anchor fields
	VirtualKeyID               string `json:"virtual_key_id,omitempty"`
	VirtualKeyRevision         string `json:"virtual_key_revision,omitempty"`
	VirtualKeyHash             string `json:"virtual_key_hash,omitempty"`     // SHA-256 of bearer token (not just ID)
	BindingID                  string `json:"binding_id,omitempty"`           // from local cache if available
	CredentialID               string `json:"credential_id,omitempty"`
	CredentialRevision         string `json:"credential_revision,omitempty"`
	RealKeyHash                string `json:"real_key_hash,omitempty"`        // SHA-256 of decrypted provider key
	CredentialFingerprint      string `json:"credential_fingerprint,omitempty"` // SHA-256 of credential_id+revision
	ProviderAccountFingerprint string `json:"provider_account_fingerprint,omitempty"`
	OAuthIdentity              string `json:"oauth_identity,omitempty"` // Email/display name for OAuth accounts (personal)

	// provider / protocol
	ProviderID   string `json:"provider_id,omitempty"`
	ProviderCode string `json:"provider_code,omitempty"`
	ProtocolType string `json:"protocol_type,omitempty"`
	RouteSource  string `json:"route_source,omitempty"`

	// usage
	Model        string `json:"model,omitempty"`
	RequestCount int    `json:"request_count"`
	InputTokens  *int64 `json:"input_tokens,omitempty"`
	OutputTokens *int64 `json:"output_tokens,omitempty"`
	TotalTokens  *int64 `json:"total_tokens,omitempty"`

	// result
	RequestStatus  string `json:"request_status"`
	HTTPStatusCode *int   `json:"http_status_code,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
	ErrorMessage   string `json:"error_message,omitempty"`
}

// ReportOpts collects all context needed to build a ReportableEvent.
type ReportOpts struct {
	EventID         string
	ProxyInstanceID string
	Route           *vkeys.ResolvedRoute
	BearerToken     string // the full "aikey_vk_..." token from the request
	Model           string
	StartTime       time.Time
	FinishedAt      time.Time
	StatusCode      int
	InputTokens     int
	OutputTokens    int
	ErrorType       string
	RealKey         string // decrypted provider key (for hashing only, never stored)
	SourceVersion      string
	ClientVersion      string
	ProxyConfigVersion string
	LoadedControlSeq   int64
	LoggedInAccountID  string // fallback account_id for personal keys
}

// BuildReportableEvent creates a ReportableEvent from the proxy request context.
func BuildReportableEvent(opts ReportOpts) ReportableEvent {
	route := opts.Route
	now := opts.FinishedAt

	var inTok, outTok, totalTok int64
	inTok = int64(opts.InputTokens)
	outTok = int64(opts.OutputTokens)
	totalTok = inTok + outTok

	status := "success"
	if opts.StatusCode >= 400 {
		status = "error"
	}

	routeSource := "personal"
	orgID := route.OrgID
	if orgID != "" {
		routeSource = "team_managed"
	} else {
		// Personal keys have no org — use "personal" as a sentinel so the
		// event passes ingest validation (org_id is required).
		orgID = "personal"
	}

	// virtual_key_hash: hash the bearer token, not just the ID.
	// The bearer token is a secret that only the legitimate key holder possesses,
	// so its hash serves as a non-forgeable audit anchor.
	vkHash := hashIfNotEmpty(opts.BearerToken)

	// credential_fingerprint: hash of credential_id + revision for cross-reference
	credFP := ""
	if route.CredentialID != "" {
		credFP = hashIfNotEmpty(route.CredentialID + ":" + route.CredentialRevision)
	}

	ev := ReportableEvent{
		EventID:         opts.EventID,
		ProxyInstanceID: opts.ProxyInstanceID,
		SchemaVersion:   1,
		SourceVersion:      opts.SourceVersion,
		ClientVersion:      opts.ClientVersion,
		ProxyConfigVersion: opts.ProxyConfigVersion,
		ProxyLoadedControlSeq: func() *int64 {
			if opts.LoadedControlSeq == 0 {
				return nil
			}
			v := opts.LoadedControlSeq
			return &v
		}(),

		EventTime:  now,
		OccurredAt: now,
		StartedAt:  &opts.StartTime,
		FinishedAt: &now,

		OrgID: orgID,
		AccountID: func() string {
			if route.AccountID != "" {
				return route.AccountID
			}
			return opts.LoggedInAccountID // fallback for personal keys
		}(),
		SeatID: route.SeatID,

		VirtualKeyID:          route.VirtualKeyID,
		VirtualKeyRevision:    route.VirtualKeyRevision,
		VirtualKeyHash:        vkHash,
		BindingID:             route.BindingID,
		CredentialID:          route.CredentialID,
		CredentialRevision:    route.CredentialRevision,
		RealKeyHash:           hashIfNotEmpty(opts.RealKey),
		CredentialFingerprint: credFP,

		ProviderID:    route.ProviderID,
		ProviderCode:  route.ProviderCode,
		ProtocolType:  route.ProtocolType,
		RouteSource:   routeSource,
		OAuthIdentity: route.OAuthIdentity,

		Model:        opts.Model,
		RequestCount: 1,
		InputTokens:  &inTok,
		OutputTokens: &outTok,
		TotalTokens:  &totalTok,

		RequestStatus:  status,
		HTTPStatusCode: &opts.StatusCode,
		ErrorCode:      opts.ErrorType,
	}
	return ev
}

// hashIfNotEmpty returns a SHA-256 hex digest, or empty string.
func hashIfNotEmpty(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
