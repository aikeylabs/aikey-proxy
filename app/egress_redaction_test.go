package app

// Fence: the node upstream proxy (the /user/settings value, or the one the
// Nodes page pushes) never puts its credentials in an error or a log line.
//
//   - buildTransportStrict's error: for a single URL it used to quote the input
//     and wrap url.Parse's error, which quotes it again. A single URL that does
//     not parse reaches it only from a config file the validator never saw
//     (startup), so it shows in buildTransport's node-egress ERROR log and
//     `aikey env`; the settings page's save and Test connectivity are refused
//     earlier by config.ValidateUpstreamProxyURL, fenced from the handlers in
//     internal/admin/egress_credential_echo_test.go (review-2.4 I-1);
//   - "upstream proxy configured" logged the URL verbatim on every load, even
//     a correct one (TODO-22);
//   - buildTransport's ERROR line carries buildTransportStrict's error.
//
// spec: R-master-central-login-6.S4 秘密不外泄（出口凭据部分）
// DEC-master-central-login-15; TODO-17, TODO-22
// bugfix: workflow/CI/bugfix/2026-09-24-egress-credentials-echoed-in-errors.md
//
// 能红: log "url", proxyURL (raw) in buildTransportStrict, or quote proxyURL in
// its url.Parse error again, and the markers appear.

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/egress"
)

const (
	redactUser = "u-MARK7"
	redactPass = "p-MARK7"
	redactCred = redactUser + ":" + redactPass + "@"
)

func assertNoProxyCredentials(t *testing.T, where, got string) {
	t.Helper()
	for _, mark := range []string{redactUser, redactPass} {
		if strings.Contains(got, mark) {
			t.Errorf("%s echoed the proxy credential %q: %s", where, mark, got)
		}
	}
}

// captureDefaultLogger sends slog's default logger to a buffer for the test.
func captureDefaultLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestBuildTransportStrict_ErrorsNeverEchoProxyCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, spec  string
		want        []string // what the error must still name
		unparseable bool     // must wrap egress.ErrUnparseableProxyURL (Ruling-35)
	}{
		{"single URL with a port that is not a number",
			"http://" + redactCred + "proxy.example.test:abc",
			[]string{"http://proxy.example.test:abc"}, true},
		{"single URL with a slash in the password",
			"http://" + redactUser + ":" + redactPass + "/x@proxy.example.test:3128",
			[]string{"http://proxy.example.test:3128"}, true},
		{"chain whose second hop has no port",
			"socks5://front.example.test:1080,socks5://" + redactCred + "exit.example.test",
			[]string{"hop 2", "socks5://exit.example.test"}, false},
		{"chain whose second hop has port 0",
			"socks5://front.example.test:1080,socks5://" + redactCred + "exit.example.test:0",
			[]string{"hop 2", "socks5://exit.example.test:0"}, false},
		{"fragment",
			"proxies:\n  - {name: exit, type: ss, server: 198.51.100.4, port: 8388, cipher: aes-128-gcm, password: " + redactPass + "}",
			nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, closer, err := buildTransportStrict(tc.spec, nil)
			if closer != nil {
				defer closer.Close()
			}
			if err == nil {
				t.Fatalf("strict accepted %s (transport=%v)", tc.name, tr != nil)
			}
			assertNoProxyCredentials(t, "buildTransportStrict", err.Error())
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not name %q, so the user cannot find the bad address", err, w)
				}
			}
			if tc.unparseable && !errors.Is(err, egress.ErrUnparseableProxyURL) {
				t.Errorf("error %q does not wrap egress.ErrUnparseableProxyURL (a local copy of the hint?)", err)
			}
		})
	}
}

// TODO-22: a CORRECT single URL was logged whole — user:password included —
// every time the node egress was loaded.
func TestBuildTransportStrict_ConfiguredLogNeverEchoesProxyCredentials(t *testing.T) {
	logs := captureDefaultLogger(t)
	_, closer, err := buildTransportStrict("http://"+redactCred+"proxy.example.test:3128", nil)
	if closer != nil {
		defer closer.Close()
	}
	if err != nil {
		t.Fatalf("a well-formed single URL must build: %v", err)
	}
	got := logs.String()
	if !strings.Contains(got, "upstream proxy configured") || !strings.Contains(got, "url=http://proxy.example.test:3128") {
		t.Fatalf("want the configured line naming http://proxy.example.test:3128, got:\n%s", got)
	}
	assertNoProxyCredentials(t, "the configured log", got)
}

func TestBuildTransport_RefusalLogNeverEchoesProxyCredentials(t *testing.T) {
	prevFault := nodeEgressBuildErr.Load()
	t.Cleanup(func() { nodeEgressBuildErr.Store(prevFault) })
	logs := captureDefaultLogger(t)

	_, closer := buildTransport("socks5://front.example.test:1080,socks5://"+redactCred+"exit.example.test", nil)
	if closer != nil {
		defer closer.Close()
	}
	got := logs.String()
	if !strings.Contains(got, "upstream_proxy spec failed to build") || !strings.Contains(got, "hop 2") {
		t.Fatalf("want the refusal ERROR naming hop 2, got:\n%s", got)
	}
	assertNoProxyCredentials(t, "the refusal log", got)
	if fault := nodeEgressBuildErr.Load(); fault == nil {
		t.Fatal("the refusal was not recorded for the egress state endpoint")
	} else {
		// Err is served by GET /admin/upstream-proxy (`aikey env`); Spec is
		// only ever reported as a fingerprint.
		assertNoProxyCredentials(t, "the recorded fault", fault.Err)
	}
}
