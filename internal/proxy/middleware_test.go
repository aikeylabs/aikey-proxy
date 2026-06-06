package proxy

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWriteJSONError_MarksAikeyOrigin pins the aikey-vs-upstream discriminator:
// every aikey-GENERATED error carries X-Aikey-Error-Source = the error code, so a
// client can tell a quota 429 (ours) from a provider rate-limit 429 (pass-through,
// which never sets this header). The body deliberately mimics a provider error
// shape, so the header — not the body — is the reliable signal.
func TestWriteJSONError_MarksAikeyOrigin(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSONError(rec, 429, "quota_error", "QUOTA_EXCEEDED_USD", "Cost ($) quota exceeded")

	if got := rec.Header().Get(HeaderAikeyErrorSource); got != "QUOTA_EXCEEDED_USD" {
		t.Fatalf("aikey-generated 429 must carry %s=<code>, got %q", HeaderAikeyErrorSource, got)
	}
	if rec.Code != 429 {
		t.Errorf("status: want 429 got %d", rec.Code)
	}
	if b := rec.Body.String(); !strings.Contains(b, `"code":"QUOTA_EXCEEDED_USD"`) || !strings.Contains(b, `"type":"quota_error"`) {
		t.Errorf("body must keep provider-shaped type + aikey code, got %s", b)
	}
}
