package events

import "time"

// UsageEvent records a single proxied request for auditing and analytics.
type UsageEvent struct {
	ID           int64     `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	VirtualKeyID string    `json:"virtual_key_id"`
	Provider     string    `json:"provider"`
	Model        string    `json:"model"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	DurationMs   int64     `json:"duration_ms"`
	StatusCode   int       `json:"status_code"`
	IsStreaming   bool      `json:"is_streaming"`
	ErrorType    string    `json:"error_type,omitempty"`
	RequestPath  string    `json:"request_path"`
}
