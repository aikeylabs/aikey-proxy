package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

func respWithBody(body string) *http.Response {
	return &http.Response{Body: io.NopCloser(strings.NewReader(body))}
}

// TestCaptureUpstreamErrorBody is the regression for the usage-detail "错误原因 /
// 无错误详情" gap: a failed request must record the REAL upstream error reason into
// the event's error_message (not the generic HTTP status text), the body must
// still reach the client (re-buffered), and a parseable provider envelope must
// surface the human-readable message rather than raw JSON.
func TestCaptureUpstreamErrorBody(t *testing.T) {
	// Real Moonshot/Kimi 429 envelope → error_code = parsed provider type;
	// error_message = RAW body (lossless; the page cleans it for display).
	reason := "Your account ... is suspended due to insufficient balance"
	body := `{"error":{"message":"` + reason + `","type":"exceeded_current_quota_error"}}`
	resp := respWithBody(body)

	gotType, gotMsg := captureUpstreamErrorBody(resp)
	if gotType != "exceeded_current_quota_error" {
		t.Fatalf("parseable envelope: want provider type, got %q", gotType)
	}
	if gotMsg != body {
		t.Fatalf("error_message must be stored RAW (lossless), want %q got %q", body, gotMsg)
	}
	// Re-buffered: the client must still receive the ORIGINAL payload (full JSON).
	after, _ := io.ReadAll(resp.Body)
	if string(after) != body {
		t.Errorf("body must be re-buffered for the client, got %q", string(after))
	}

	// Unparseable / unknown shape → empty type, raw body for the message.
	raw := "upstream exploded, not json"
	if gt, gm := captureUpstreamErrorBody(respWithBody(raw)); gt != "" || gm != raw { //nolint:bodyclose // respWithBody is a NopCloser; captureUpstreamErrorBody reads and closes it
		t.Errorf("unparseable body: want (\"\", raw), got (%q, %q)", gt, gm)
	}

	// Truncation: an oversized raw body is trimmed + marked.
	bigBody := strings.Repeat("x", errorBodyCap+500)
	if _, gm := captureUpstreamErrorBody(respWithBody(bigBody)); len(gm) <= errorBodyCap || !strings.HasSuffix(gm, "…") { //nolint:bodyclose // respWithBody is a NopCloser; captureUpstreamErrorBody reads and closes it
		t.Errorf("oversized body must be truncated to cap + marker, got len=%d", len(gm))
	}

	// Nil-safe: nil response / nil body return ("","") without panicking.
	if gt, gm := captureUpstreamErrorBody(nil); gt != "" || gm != "" {
		t.Errorf("nil resp must return empty, got (%q,%q)", gt, gm)
	}
	if gt, gm := captureUpstreamErrorBody(&http.Response{}); gt != "" || gm != "" {
		t.Errorf("nil body must return empty, got (%q,%q)", gt, gm)
	}
}

// TestCaptureUpstreamErrorBody_CapIsCharactersNotBytes is the fence for bugfix
// 2026-09-23-collector-data-error-classified-transient: the collector stores
// error_message in VARCHAR(1024) and PostgreSQL counts CHARACTERS. The old cap
// was 2048 BYTES, produced a 2049-character value, PostgreSQL answered SQLSTATE
// 22001 and the proxy re-sent that batch every 30 s for two weeks. The cap is
// now errorBodyCap characters + "…" (= 1024 in total) and never splits a rune.
func TestCaptureUpstreamErrorBody_CapIsCharactersNotBytes(t *testing.T) {
	cjk := strings.Repeat("错", 3000)                     // 9000 bytes, 3000 characters
	_, gm := captureUpstreamErrorBody(respWithBody(cjk)) //nolint:bodyclose // respWithBody is a NopCloser; captureUpstreamErrorBody reads and closes it
	if n := utf8.RuneCountInString(gm); n != errorBodyCap+1 {
		t.Fatalf("multibyte body: want %d chars (cap + marker), got %d chars / %d bytes", errorBodyCap+1, n, len(gm))
	}
	if !utf8.ValidString(gm) || !strings.HasSuffix(gm, "…") {
		t.Fatalf("multibyte body: cap must keep UTF-8 valid and end with the marker")
	}
	if errorBodyCap+1 > 1024 {
		t.Fatalf("errorBodyCap+marker = %d exceeds the collector's error_message VARCHAR(1024)", errorBodyCap+1)
	}
	ascii := strings.Repeat("x", 5000)
	_, gm = captureUpstreamErrorBody(respWithBody(ascii)) //nolint:bodyclose // see above
	if n := utf8.RuneCountInString(gm); n != errorBodyCap+1 {
		t.Fatalf("ascii body: want %d chars, got %d", errorBodyCap+1, n)
	}
	if capErrorText("short") != "short" {
		t.Fatalf("values under the cap must pass through unchanged")
	}
	exact := strings.Repeat("y", errorBodyCap)
	if capErrorText(exact) != exact {
		t.Fatalf("a value exactly at the cap must pass through unchanged")
	}
}
