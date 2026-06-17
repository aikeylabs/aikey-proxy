package supervisor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

func TestDistinctSeatIDsFromKeys(t *testing.T) {
	mks := []vault.ManagedKey{
		{SeatID: "seat-b"},
		{SeatID: "seat-a"},
		{SeatID: "seat-a"}, // dup
		{SeatID: ""},       // skipped
	}
	got := distinctSeatIDsFromKeys(mks)
	want := []string{"seat-a", "seat-b"} // deduped + sorted
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestFetchQuotaPolicy_ParsesAndSignsStably(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		w.WriteHeader(http.StatusOK)
		// Returned out of subject-id order on purpose — the signature must be stable.
		_, _ = w.Write([]byte(`{"subjects":[
			{"subject_id":"seat-b","subject_kind":"seat","rules":[{"metric":"tokens","period":"daily","limit_amount":2}]},
			{"subject_id":"seat-a","subject_kind":"seat","rules":[{"metric":"tokens","period":"daily","limit_amount":1}]}
		]}`))
	}))
	defer srv.Close()

	subs, sig, ok := fetchQuotaPolicy(context.Background(), srv.URL, "org1", []string{"seat-a", "seat-b"})
	if !ok {
		t.Fatal("ok=false, want true")
	}
	if len(subs) != 2 {
		t.Fatalf("subjects=%d, want 2", len(subs))
	}
	// Query carries tenant + seats.
	if gotPath != "/v1/quota/policy?tenant=org1&seats=seat-a%2Cseat-b" {
		t.Errorf("request path = %q", gotPath)
	}
	// Signature is order-stable: a second call with the same content (any order)
	// yields the same signature, so steady state is a no-op.
	_, sig2, _ := fetchQuotaPolicy(context.Background(), srv.URL, "org1", []string{"seat-a", "seat-b"})
	if sig != sig2 {
		t.Errorf("signature not stable across calls: %q vs %q", sig, sig2)
	}
}

func TestFetchQuotaPolicy_ErrorsKeepLastKnown(t *testing.T) {
	// Non-200 and unreachable both yield ok=false so the caller keeps the last
	// known policy (never flaps enforcement on a transient miss).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, _, ok := fetchQuotaPolicy(context.Background(), srv.URL, "org1", []string{"seat-a"}); ok {
		t.Error("non-200 must yield ok=false")
	}
	if _, _, ok := fetchQuotaPolicy(context.Background(), "http://127.0.0.1:0", "org1", []string{"seat-a"}); ok {
		t.Error("unreachable must yield ok=false")
	}
}

func TestFetchQuotaPolicy_EmptySubjectsIsValidChange(t *testing.T) {
	// An empty (but well-formed) subjects list is a legitimate answer (the last rule
	// was deleted) — ok=true with zero subjects, distinct from a fetch error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"subjects":[]}`))
	}))
	defer srv.Close()
	subs, _, ok := fetchQuotaPolicy(context.Background(), srv.URL, "org1", []string{"seat-a"})
	if !ok {
		t.Fatal("empty subjects must be ok=true")
	}
	if len(subs) != 0 {
		t.Errorf("want 0 subjects, got %d", len(subs))
	}
}
