package supervisor

// dialect_bridge_rail_test.go — fences for the control-plane dialect-bridge switch.
//
// Design: roadmap20260320/技术实现/update/
//
//	20260912-ChatCompletions桥接开关-控制面下发-技术方案.md

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

func bridgeSupervisor(localEnabled bool) *Supervisor {
	return &Supervisor{cfg: &config.Config{
		ChatCompletionsBridge: config.ChatCompletionsBridgeConfig{Enabled: localEnabled},
	}}
}

func boolPtr(v bool) *bool { return &v }

// 🔴 THE trap this whole design had to avoid.
//
// The switch is injected into the proxy when a generation is BUILT, and a
// generation is rebuilt on every Reload — which the vault's 5s change_seq tick, a
// compliance policy change and a quota policy change all trigger, none of them
// related to this feature. If the generation path read the config file while the
// rail wrote the control plane's answer, an administrator would turn the bridge
// off in the console, watch it take effect, and watch it turn itself back on
// minutes later with nothing in any log.
//
// 能红: change applyChatCompletionsBridge to read s.cfg.ChatCompletionsBridge.Enabled
// instead of effectiveChatCompletionsBridgeEnabled().
func TestDialectBridge_AReloadDoesNotOverwriteTheControlPlanesAnswer(t *testing.T) {
	s := bridgeSupervisor(true)          // this machine's aikey-user.yaml says ON
	s.masterBridge.Store(boolPtr(false)) // the console says OFF

	// What the rail does to the running proxy.
	live := &proxy.Proxy{}
	s.applyChatCompletionsBridge(live)
	if live.ChatCompletionsBridgeEnabled() {
		t.Fatal("the rail applied the LOCAL value; the control plane's answer was ignored")
	}

	// What a Reload does: a brand-new generation, wired from scratch.
	rebuilt := &proxy.Proxy{}
	s.applyChatCompletionsBridge(rebuilt)
	if rebuilt.ChatCompletionsBridgeEnabled() {
		t.Fatal("a rebuilt generation re-injected the local config value, overwriting the control " +
			"plane's answer — the switch would flip back on its own on the next unrelated reload")
	}
}

// The runtime fence above can only see the helper. This one holds the other half:
// that the generation path still GOES through the helper. A future edit that
// inlines the config read into buildGeneration would leave the fence above green
// while reintroducing the exact defect.
//
// 🔴 A fence matching source text goes blind if the code is restructured — so it
// is deliberately paired with the runtime fence rather than standing alone, and
// it asserts the NEGATIVE (nobody else reads the field) rather than matching one
// call shape.
func TestDialectBridge_OnlyTheRailReconcilesTheTwoSources(t *testing.T) {
	src := readSupervisorSource(t, "supervisor.go")
	if strings.Contains(src, "ChatCompletionsBridge.Enabled") {
		t.Fatal("supervisor.go reads cfg.ChatCompletionsBridge.Enabled directly. " +
			"The local file and the control plane must be reconciled in exactly one place " +
			"(effectiveChatCompletionsBridgeEnabled in dialect_bridge_rail.go), or a reload " +
			"will re-inject the local value over a pushed one.")
	}
}

// 能红: delete s.dialectBridgeRail() from the newRailSet(...) call. An
// unregistered rail is silent — the console switch stores fine, shows fine, and
// never reaches a single worker.
func TestDialectBridgeRailIsRegisteredIntoTheRailSet(t *testing.T) {
	src := readSupervisorSource(t, "supervisor.go")
	// (?m) so $ means end-of-LINE. Without it Go's $ is end-of-TEXT and the
	// match fails against correct source — the same mistake the fallback rail's
	// fence documents, made here first time out.
	line := regexp.MustCompile(`(?m)newRailSet\(.*$`)
	m := line.FindString(src)
	if m == "" {
		t.Fatal("no newRailSet(...) call found in supervisor.go")
	}
	if !strings.Contains(m, "s.dialectBridgeRail()") {
		t.Fatalf("dialectBridgeRail is not registered into the railset: %s", m)
	}
}

func bridgePolicyServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// 🔴 Absence is not "off". A deployment that enabled the bridge in its own
// aikey-user.yaml must keep it enabled until an administrator actually answers —
// staging has two such workers, and this is what keeps them working across the
// upgrade that ships the console switch.
//
// 能红: decode into a plain bool (absent → false), or store &false on an absent field.
func TestDialectBridge_AnAbsentFieldLeavesTheLocalConfigInCharge(t *testing.T) {
	s := bridgeSupervisor(true) // local says ON
	srv := bridgePolicyServer(t, http.StatusOK, `{}`)

	if err := s.syncDialectBridge(context.Background(), nil, srv.URL, ""); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if s.masterBridge.Load() != nil {
		t.Fatal("an absent field was stored as an answer; absence means the control plane has no opinion")
	}
	if !s.effectiveChatCompletionsBridgeEnabled() {
		t.Fatal("the bridge was switched OFF by a policy that said nothing at all")
	}
	if got := s.BridgeSwitchSource(); got != "local_config" {
		t.Fatalf("source = %q, want local_config", got)
	}
}

// Both answered values must win over the local file — including false, or the
// console could never turn the bridge off on a fleet whose config files say on,
// which is one of the two things it exists to do.
func TestDialectBridge_AnAnsweredValueWinsOverTheLocalFile(t *testing.T) {
	for _, tc := range []struct {
		name  string
		local bool
		body  string
		want  bool
	}{
		{"console turns it off while the file says on", true, `{"enabled":false}`, false},
		{"console turns it on while the file says off", false, `{"enabled":true}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := bridgeSupervisor(tc.local)
			live := &proxy.Proxy{}
			srv := bridgePolicyServer(t, http.StatusOK, tc.body)

			if err := s.syncDialectBridge(context.Background(), &generation{proxy: live}, srv.URL, ""); err != nil {
				t.Fatalf("sync: %v", err)
			}
			if got := s.effectiveChatCompletionsBridgeEnabled(); got != tc.want {
				t.Fatalf("effective = %v, want %v", got, tc.want)
			}
			// Applied to the RUNNING proxy, without a reload and without a restart.
			if got := live.ChatCompletionsBridgeEnabled(); got != tc.want {
				t.Fatalf("the live proxy still reads %v; the answer reached the supervisor but not the request path", got)
			}
			if got := s.BridgeSwitchSource(); got != "control_plane" {
				t.Fatalf("source = %q, want control_plane", got)
			}
		})
	}
}

// A control-plane blip must not move the switch. Answering "off" on an error
// would cut clients off mid-conversation, and the bridge is not a security
// boundary — the upstream allowlist is, and that never leaves local config.
func TestDialectBridge_KeepsTheLastKnownAnswerWhenTheControlPlaneFails(t *testing.T) {
	s := bridgeSupervisor(false)
	ok := bridgePolicyServer(t, http.StatusOK, `{"enabled":true}`)
	if err := s.syncDialectBridge(context.Background(), nil, ok.URL, ""); err != nil {
		t.Fatalf("first sync: %v", err)
	}

	broken := bridgePolicyServer(t, http.StatusInternalServerError, `nope`)
	if err := s.syncDialectBridge(context.Background(), nil, broken.URL, ""); err == nil {
		t.Fatal("a 500 must be a counted failure, or /status would show a healthy rail while the answer is stale")
	}
	if !s.effectiveChatCompletionsBridgeEnabled() {
		t.Fatal("a failed cycle changed the switch; keep-last-known is the posture here")
	}
}

// An older control plane has no such route. That is a successful cycle
// establishing there is no mandate — not a failure, or every deployment that has
// not upgraded its control plane yet would show a red rail for ever.
func TestDialectBridge_AnOlderControlPlaneIsNotAFailure(t *testing.T) {
	s := bridgeSupervisor(true)
	srv := bridgePolicyServer(t, http.StatusNotFound, `not found`)

	if err := s.syncDialectBridge(context.Background(), nil, srv.URL, ""); err != nil {
		t.Fatalf("a 404 must not be counted as a failure, got: %v", err)
	}
	if s.masterBridge.Load() != nil {
		t.Fatal("a 404 stored an answer; it means this control plane has no switch at all")
	}
	if !s.effectiveChatCompletionsBridgeEnabled() {
		t.Fatal("a 404 switched the bridge off under a deployment whose local config enables it")
	}
}
