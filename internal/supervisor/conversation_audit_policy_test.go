package supervisor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchConversationAuditPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/conversation-audit/policy" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"enabled":true,"max_bytes":262144}`))
	}))
	defer srv.Close()

	enabled, maxBytes, ok := fetchConversationAuditPolicy(context.Background(), srv.URL, "default")
	if !ok || !enabled || maxBytes != 262144 {
		t.Fatalf("fetch=(enabled=%v,max=%d,ok=%v) want (true,262144,true)", enabled, maxBytes, ok)
	}

	// non-200 → ok=false so the caller keeps the last-known value (no flap)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if _, _, ok := fetchConversationAuditPolicy(context.Background(), bad.URL, "default"); ok {
		t.Fatalf("non-200 must return ok=false (keep last-known)")
	}

	// unreachable → ok=false
	if _, _, ok := fetchConversationAuditPolicy(context.Background(), "http://127.0.0.1:1", "default"); ok {
		t.Fatalf("unreachable must return ok=false")
	}
}

// The capture gate is a lock-free atomic, default OFF.
func TestConversationAuditEnabled_AtomicGate(t *testing.T) {
	var s Supervisor
	if s.ConversationAuditEnabled() {
		t.Fatalf("default conversation-audit gate must be OFF")
	}
	if s.ConversationAuditMaxBytes() != 0 {
		t.Fatalf("default max_bytes must be 0 (capture default applies)")
	}
	s.convAuditEnabled.Store(true)
	s.convAuditMaxBytes.Store(999)
	if !s.ConversationAuditEnabled() || s.ConversationAuditMaxBytes() != 999 {
		t.Fatalf("after store: enabled=%v max=%d want true/999", s.ConversationAuditEnabled(), s.ConversationAuditMaxBytes())
	}
}
