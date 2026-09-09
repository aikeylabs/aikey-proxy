//go:build ignore

// fakemcp is a minimal, REAL MCP server over stdio, compiled and run as an
// actual child process by the P5 fences.
//
// 🔴 It is a separate program, not an in-process fake, because every property
// P5 has to prove is a property of a real OS process: that its descendants are
// reaped, that the credential is in its environment and not in its argv, that
// its stderr is drained, that it can crash and be restarted. An in-process fake
// can demonstrate none of those.
//
// Behaviour is driven by environment variables so one binary covers every case:
//
//	FAKEMCP_SECRET_ENV   name of the variable the credential should arrive in
//	FAKEMCP_SPAWN_WORKER spawn a long-lived grandchild and print its pid to stderr
//	FAKEMCP_CRASH_AFTER  exit non-zero after N successful tool calls
//	FAKEMCP_STDOUT_NOISE write a non-JSON banner to stdout before serving
//	FAKEMCP_HANG         never answer tools/call
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
}

func main() {
	if os.Getenv("FAKEMCP_STDOUT_NOISE") != "" {
		fmt.Fprintln(os.Stdout, "fake-mcp v1 starting up")
	}
	if os.Getenv("FAKEMCP_SPAWN_WORKER") != "" {
		// A grandchild that long outlives the test — the `npx → node` shape.
		w := exec.Command("/bin/sh", "-c", "sleep 300")
		if err := w.Start(); err == nil {
			fmt.Fprintf(os.Stderr, "WORKER:%d\n", w.Process.Pid)
		}
	}
	crashAfter, _ := strconv.Atoi(os.Getenv("FAKEMCP_CRASH_AFTER"))
	calls := 0

	out := bufio.NewWriter(os.Stdout)
	reply := func(id json.RawMessage, result any) {
		raw, _ := json.Marshal(result)
		body, _ := json.Marshal(envelope{JSONRPC: "2.0", ID: id, Result: raw})
		_, _ = out.Write(append(body, '\n'))
		_ = out.Flush()
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var env envelope
		if json.Unmarshal([]byte(line), &env) != nil {
			continue
		}
		switch env.Method {
		case "initialize":
			reply(env.ID, map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "fake-mcp", "version": "1"},
			})
		case "notifications/initialized":
			// no reply
		case "tools/list":
			reply(env.ID, map[string]any{"tools": []map[string]any{{
				"name":        "echo_secret_presence",
				"description": "Reports whether the credential arrived in the environment.",
				"inputSchema": map[string]any{"type": "object"},
			}}})
		case "tools/call":
			if os.Getenv("FAKEMCP_HANG") != "" {
				time.Sleep(10 * time.Minute)
			}
			calls++
			if crashAfter > 0 && calls > crashAfter {
				os.Exit(3)
			}
			// Report what the child can see, so the fence can prove the
			// credential really did arrive — otherwise "not in argv" would pass
			// against a build that simply never delivered it.
			got := ""
			if name := os.Getenv("FAKEMCP_SECRET_ENV"); name != "" {
				got = os.Getenv(name)
			}
			reply(env.ID, map[string]any{"content": []map[string]any{
				{"type": "text", "text": "secret_from_env=" + got},
			}})
		}
	}
}
