#!/usr/bin/env bash
# Mutation drill for the delegation-boundary fences (P15 · K1 · 2026-09-03).
#
# WHY THIS EXISTS
# ---------------
# A green fence proves nothing. It proves something only once you have watched
# it go RED for the defect it claims to guard. Every rule drilled below guards
# something that, today, is enforced by nothing else — so each gets a mutation
# that reintroduces the original defect, and the drill fails if the named test
# still passes.
#
# Four ways a drill lies, all guarded against here:
#   - a mutation that matched nothing (checked with cmp: NO-OP is a failure)
#   - a `-run` selector matching no test, which `go test` reports as SUCCESS
#     (checked by requiring the word "PASS"/"FAIL" for the named test)
#   - a stale build cache answering instead of the mutated source (-count=1)
#   - a mutation left behind because the script died early (trap on EXIT,
#     and SIGPIPE-safe: no `| head` anywhere in this file)
#
# Spec:  roadmap20260320/技术实现/update/20260903-MCP网关-Agent委派与执行身份.md
# Fences: 测试checklist §D D-79..D-95 · tasks 15.F1..15.F16
# Usage: make drill-delegation
set -uo pipefail

cd "$(dirname "$0")/.."
PROXY_DIR="$PWD"
WIRE_DIR="$PWD/../pkg/mcpwire"

CLI_DIR="$PWD/../aikey-cli"

WIRE_SRC="$WIRE_DIR/delegation.go"
PROXY_SRC="$PROXY_DIR/internal/mcp/delegation.go"
CLI_SRC="$CLI_DIR/src/mcp_guard.rs"
# P15 · K4 — the harness adaptation layer (task 15.D).
CLI_HARNESS="$CLI_DIR/src/mcp_harness.rs"
CTL_DIR="$PWD/../aikey-control-master/service"
CTL_SRC="$CTL_DIR/internal/mcpgateway/delegation.go"
CTL_STORE="$CTL_DIR/internal/mcpgateway/storage.go"
CTL_DOMAIN="$CTL_DIR/internal/mcpgateway/domain.go"
# P15 · K3 (executor attribution, task 15.C).
CTL_CALLLOG="$CTL_DIR/internal/mcpgateway/calllog.go"
CTL_CALLS="$CTL_DIR/internal/mcpgateway/calls.go"
# P15 · 15.16 — the delegation gate's own activity, seat half and control half.
CTL_GUARD="$CTL_DIR/internal/mcpgateway/guardactivity.go"
CTL_CREDDEL="$CTL_DIR/internal/mcpgateway/credential_delivery.go"
# bugfix 2026-09-08 — the two defects the live failure-path run found.
MCP_POLICY="$PROXY_DIR/internal/mcp/policy.go"
SUP_RAIL="$PROXY_DIR/internal/supervisor/mcp_credential_rail.go"
MCP_CALLREC="$PROXY_DIR/internal/mcp/callrecord.go"
MCP_UPSTREAM="$PROXY_DIR/internal/mcp/upstream.go"
ADMIN_SRC="$PROXY_DIR/internal/admin/handlers.go"
ACTOR_YAML="$PROXY_DIR/internal/proxy/sessionid/actor-fingerprint.yaml"

BACKUP_DIR="$(mktemp -d -t delegation_drill)"
cp "$WIRE_SRC" "$BACKUP_DIR/wire.go"
cp "$PROXY_SRC" "$BACKUP_DIR/proxy.go"
cp "$CLI_SRC" "$BACKUP_DIR/cli.rs"
cp "$CLI_HARNESS" "$BACKUP_DIR/cli_harness.rs"
cp "$CTL_SRC" "$BACKUP_DIR/ctl.go"
cp "$CTL_STORE" "$BACKUP_DIR/ctl_storage.go"
cp "$CTL_DOMAIN" "$BACKUP_DIR/ctl_domain.go"
cp "$CTL_CALLLOG" "$BACKUP_DIR/ctl_calllog.go"
cp "$CTL_CALLS"   "$BACKUP_DIR/ctl_calls.go"
cp "$MCP_CALLREC" "$BACKUP_DIR/mcp_callrecord.go"
cp "$MCP_UPSTREAM" "$BACKUP_DIR/mcp_upstream.go"
cp "$ADMIN_SRC"   "$BACKUP_DIR/admin_handlers.go"
cp "$ACTOR_YAML"  "$BACKUP_DIR/actor.yaml"
cp "$CTL_GUARD"   "$BACKUP_DIR/ctl_guard.go"
cp "$CTL_CREDDEL" "$BACKUP_DIR/ctl_creddel.go"
cp "$SUP_RAIL"    "$BACKUP_DIR/sup_rail.go"
cp "$MCP_POLICY"  "$BACKUP_DIR/mcp_policy.go"

FAILED=0
RAN=0

restore() {
  cp "$BACKUP_DIR/wire.go" "$WIRE_SRC"
  cp "$BACKUP_DIR/proxy.go" "$PROXY_SRC"
  cp "$BACKUP_DIR/cli.rs" "$CLI_SRC"
  cp "$BACKUP_DIR/cli_harness.rs" "$CLI_HARNESS"
  cp "$BACKUP_DIR/ctl.go" "$CTL_SRC"
  cp "$BACKUP_DIR/ctl_storage.go" "$CTL_STORE"
  cp "$BACKUP_DIR/ctl_domain.go" "$CTL_DOMAIN"
  cp "$BACKUP_DIR/ctl_calllog.go" "$CTL_CALLLOG"
  cp "$BACKUP_DIR/ctl_calls.go" "$CTL_CALLS"
  cp "$BACKUP_DIR/mcp_callrecord.go" "$MCP_CALLREC"
  cp "$BACKUP_DIR/mcp_upstream.go" "$MCP_UPSTREAM"
  cp "$BACKUP_DIR/admin_handlers.go" "$ADMIN_SRC"
  cp "$BACKUP_DIR/actor.yaml" "$ACTOR_YAML"
  cp "$BACKUP_DIR/ctl_guard.go" "$CTL_GUARD"
  cp "$BACKUP_DIR/ctl_creddel.go" "$CTL_CREDDEL"
  cp "$BACKUP_DIR/sup_rail.go" "$SUP_RAIL"
  cp "$BACKUP_DIR/mcp_policy.go" "$MCP_POLICY"
}
# 🔴 EXIT covers the normal path AND every error path. INT/TERM are listed
# explicitly because a Ctrl-C in the middle of a drill is exactly when a
# mutation gets left behind in the working tree — this repo has been bitten by
# that before (a drill died between "wrote the mutation" and "restored", and the
# next run snapshotted the poisoned file and reported "byte-identical", which
# was true and worthless).
trap 'restore; rm -rf "$BACKUP_DIR"' EXIT INT TERM

# drill <name> <dir> <src> <test-selector> <python-mutation>
drill() {
  local name="$1" dir="$2" src="$3" selector="$4" mutation="$5"
  local backup
  case "$src" in
    "$WIRE_SRC")    backup="$BACKUP_DIR/wire.go" ;;
    "$CLI_SRC")     backup="$BACKUP_DIR/cli.rs" ;;
    "$MCP_CALLREC") backup="$BACKUP_DIR/mcp_callrecord.go" ;;
    "$MCP_UPSTREAM") backup="$BACKUP_DIR/mcp_upstream.go" ;;
    "$ADMIN_SRC")   backup="$BACKUP_DIR/admin_handlers.go" ;;
    "$ACTOR_YAML")  backup="$BACKUP_DIR/actor.yaml" ;;
    "$SUP_RAIL")    backup="$BACKUP_DIR/sup_rail.go" ;;
    "$MCP_POLICY")  backup="$BACKUP_DIR/mcp_policy.go" ;;
    *)              backup="$BACKUP_DIR/proxy.go" ;;
  esac

  restore
  RAN=$((RAN + 1))

  python3 - "$src" <<PY
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text(encoding="utf-8")
$mutation
p.write_text(s, encoding="utf-8")
PY

  if cmp -s "$src" "$backup"; then
    echo "  NO-OP        $name — mutation matched nothing; this drill proves nothing"
    FAILED=1
    restore
    return
  fi

  local out
  out="$(cd "$dir" && go test ./... -run "$selector" -count=1 2>&1)"

  if printf '%s' "$out" | grep -q -- "--- FAIL: $selector\|^FAIL\|build failed\|cannot use\|undefined:"; then
    echo "  RED          $name"
  else
    echo "  STAYED GREEN $name — the fence did not catch its own defect"
    echo "$out" | sed 's/^/               /'
    FAILED=1
  fi
  restore
}

# drill_rust <name> <test-name> <python-mutation>
#
# 🔴 `--exact` matters: without it a typo in the test name matches NOTHING and
# cargo exits 0, which this script would read as "the fence stayed green" — a
# lie in the safe-looking direction. The empty-selector check below turns that
# into a loud NO-OP instead.
drill_rust() {
  local name="$1" test_name="$2" mutation="$3" src="${4:-$CLI_SRC}"
  local backup="$BACKUP_DIR/cli.rs"
  [ "$src" = "$CLI_HARNESS" ] && backup="$BACKUP_DIR/cli_harness.rs"
  restore
  RAN=$((RAN + 1))

  python3 - "$src" <<RUSTMUT
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text(encoding="utf-8")
$mutation
p.write_text(s, encoding="utf-8")
RUSTMUT

  if cmp -s "$src" "$backup"; then
    echo "  NO-OP        $name — mutation matched nothing; this drill proves nothing"
    FAILED=1
    restore
    return
  fi

  local out
  out="$(cd "$CLI_DIR" && cargo test --bin aikey "$test_name" -- --exact 2>&1)"

  if printf '%s' "$out" | grep -q "1 passed"; then
    echo "  STAYED GREEN $name — the fence did not catch its own defect"
    FAILED=1
  elif printf '%s' "$out" | grep -q "0 passed; 0 failed"; then
    echo "  NO-OP        $name — the test selector matched nothing (renamed test?)"
    FAILED=1
  elif printf '%s' "$out" | grep -q "test result: FAILED"; then
    echo "  RED          $name"
  elif printf '%s' "$out" | grep -q "error\[E\|could not compile"; then
    echo "  RED          $name (compile)"
  else
    echo "  UNCLEAR      $name — could not classify the run"
    printf '%s' "$out" | tail -20 | sed 's/^/               /'
    FAILED=1
  fi
  restore
}

# drill_ctl <name> <src> <test-name> <python-mutation>
#
# 🔴 GOWORK=off: aikey-control-master/service is NOT in the workspace, so a run
# that inherits the workspace resolves a DIFFERENT set of sibling modules than
# the one this module actually ships against. The repo has already been caught
# by that ("outside module roots" is not a compile error, it is a different
# build).
drill_ctl() {
  local name="$1" src="$2" test_name="$3" mutation="$4"
  local backup
  case "$src" in
    "$CTL_SRC")     backup="$BACKUP_DIR/ctl.go" ;;
    "$CTL_STORE")   backup="$BACKUP_DIR/ctl_storage.go" ;;
    "$CTL_CALLLOG") backup="$BACKUP_DIR/ctl_calllog.go" ;;
    "$CTL_CALLS")   backup="$BACKUP_DIR/ctl_calls.go" ;;
    "$CTL_GUARD")   backup="$BACKUP_DIR/ctl_guard.go" ;;
    "$CTL_CREDDEL") backup="$BACKUP_DIR/ctl_creddel.go" ;;
    *)              backup="$BACKUP_DIR/ctl_domain.go" ;;
  esac

  restore
  RAN=$((RAN + 1))

  python3 - "$src" <<CTLMUT
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text(encoding="utf-8")
$mutation
p.write_text(s, encoding="utf-8")
CTLMUT

  if cmp -s "$src" "$backup"; then
    echo "  NO-OP        $name — mutation matched nothing; this drill proves nothing"
    FAILED=1
    restore
    return
  fi

  local out
  out="$(cd "$CTL_DIR" && GOWORK=off go test ./internal/mcpgateway/ -run "^$test_name\$" -count=1 2>&1)"

  if printf '%s' "$out" | grep -q -- "--- FAIL: $test_name\|^FAIL\|build failed\|cannot use\|undefined:\|no required module"; then
    echo "  RED          $name"
  elif printf '%s' "$out" | grep -q "no tests to run"; then
    echo "  NO-OP        $name — the selector matched no test (renamed?)"
    FAILED=1
  else
    echo "  STAYED GREEN $name — the fence did not catch its own defect"
    printf '%s' "$out" | tail -12 | sed 's/^/               /'
    FAILED=1
  fi
  restore
}

echo "== delegation fences · mutation drill =="
echo

echo "-- pkg/mcpwire"

# D-80 / I31 — the decision must never be able to carry authority (D-24: the
# gate issues NOTHING; a second credential is a second revocation path).
drill "D-80 decision carries no credential" "$WIRE_DIR" "$WIRE_SRC" \
  "TestDecisionCarriesNoCredentialShape" \
  's = s.replace("\tStale bool `json:\"stale,omitempty\"`", "\tStale bool `json:\"stale,omitempty\"`\n\tToken string `json:\"token,omitempty\"`")'

# D-87 / I37 / R66 — the hook reply must be structurally unable to rewrite the
# harness tool input.
drill "D-87 hook reply cannot rewrite input" "$WIRE_DIR" "$WIRE_SRC" \
  "TestHookDecisionCannotCarryUpdatedInput" \
  's = s.replace("\tPermissionDecisionReason string `json:\"permissionDecisionReason,omitempty\"`", "\tPermissionDecisionReason string `json:\"permissionDecisionReason,omitempty\"`\n\tUpdatedInput map[string]any `json:\"updatedInput,omitempty\"`")'

# D-88 / I38 — delegation codes must not enter the frozen MCP wire catalogue.
drill "D-88 delegation code kept off the wire catalogue" "$WIRE_DIR" "$WIRE_SRC" \
  "TestDelegationCodesAreNotInTheMCPWireCatalog" \
  's = s.replace("var DelegationErrorCatalog = []DelegationErrorSpec{", "func init() { ErrorCodeCatalog = append(ErrorCodeCatalog, ErrorCodeSpec{Code: ErrorCode(DelegationDenied)}) }\n\nvar DelegationErrorCatalog = []DelegationErrorSpec{")'

# D-94 — the same tool has two names; matching one makes the gate fail silently.
drill "D-94 gate recognises both Agent and Task" "$WIRE_DIR" "$WIRE_SRC" \
  "TestBothDelegationToolNamesAreRecognised" \
  's = s.replace("return toolName == DelegationToolAgent || toolName == DelegationToolTask", "return toolName == DelegationToolAgent")'

# D-95 — "main agent" is field ABSENCE, never an empty string.
drill "D-95 main actor is absence not empty" "$WIRE_DIR" "$WIRE_SRC" \
  "TestMainActorIsFieldAbsenceNotEmptyString" \
  's = s.replace("func (e HookEvent) IsMainActor() bool { return e.AgentID == nil }", "func (e HookEvent) IsMainActor() bool { return e.AgentID == nil || *e.AgentID == \"\" }")'

# D-89 — "allowed but narrowed" must stay its own event.
drill "D-89 narrowed is its own event" "$WIRE_DIR" "$WIRE_SRC" \
  "TestNarrowedIsItsOwnEvent" \
  's = s.replace("\tVerdictNarrow: EventDelegationNarrowed,", "\tVerdictNarrow: EventDelegationAllowed,")'

# Narrowing must not interrupt the developer.
drill "narrow renders as allow to the harness" "$WIRE_DIR" "$WIRE_SRC" \
  "TestNarrowRendersAsAllowToTheHarness" \
  's = s.replace("\tif d.Verdict == VerdictDeny {", "\tif d.Verdict == VerdictDeny || d.Verdict == VerdictNarrow {")'

echo
echo "-- aikey-proxy/internal/mcp"

# D-79 / I30 / R60 — child ⊆ parent ⊆ seat. The intersection IS the invariant.
drill "D-79 child is always a subset of parent" "$PROXY_DIR" "$PROXY_SRC" \
  "TestChildIsAlwaysASubsetOfParent" \
  's = s.replace("\tchild := intersect(parent, normalizeSlugs(tier.ToolsetSlugs))", "\tchild := normalizeSlugs(tier.ToolsetSlugs)")'

# D-90 / D-27 — the zero value must behave exactly like today.
drill "D-90 unconfigured org is pass-through" "$PROXY_DIR" "$PROXY_SRC" \
  "TestZeroPolicyAllowsEverything" \
  's = s.replace("\tif len(pol.Tiers) == 0 {\n\t\treturn mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Toolsets: parent}\n\t}\n\n", "")'

# MaxDepth三态 — zero must mean NONE, not unlimited (the limit=0 trap).
drill "MaxDepth 0 means none, not unlimited" "$PROXY_DIR" "$PROXY_SRC" \
  "TestMaxDepthZeroMeansNoneNotUnlimited" \
  's = s.replace("if tier.MaxDepth != nil && req.Depth > *tier.MaxDepth {", "if tier.MaxDepth != nil && *tier.MaxDepth > 0 && req.Depth > *tier.MaxDepth {")'

# nil vs empty ToolsetSlugs — "does not narrow" vs "narrows to nothing".
drill "nil toolsets is not an empty toolset" "$PROXY_DIR" "$PROXY_SRC" \
  "TestNilToolsetsIsNotAnEmptyToolset" \
  's = s.replace("\tif tier.ToolsetSlugs == nil {", "\tif len(tier.ToolsetSlugs) == 0 {")'

# R61 / D-24 口径 — a refusal must say WHO refused (the harness refuses too).
drill "refusal names AiKey and the tier" "$PROXY_DIR" "$PROXY_SRC" \
  "TestDenialReasonNamesAikeyAndTheTier" \
  's = s.replace("b.WriteString(\"AiKey refused this delegation\")", "b.WriteString(\"Refused\")")'

# D-84 / I35 — the decision is local; no network on the spawn path.
drill "D-84 evaluated without network" "$PROXY_DIR" "$PROXY_SRC" \
  "TestDelegationIsEvaluatedWithoutNetwork" \
  's = s.replace("import (\n\t\"context\"", "import (\n\t_ \"net/http\"\n\n\t\"context\"")'

# D-85 / D-29 — a fail-open must be FLAGGED, or it is indistinguishable from a
# working gate.
drill "D-85 fail-open is flagged stale" "$PROXY_DIR" "$PROXY_SRC" \
  "TestNeverPolledAllowsAndFlagsStale" \
  's = s.replace("\tif !g.store.Synced() {\n\t\treturn mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Stale: true}\n\t}", "\tif !g.store.Synced() {\n\t\treturn mcpwire.Decision{Verdict: mcpwire.VerdictAllow}\n\t}")'

# D-86 / D-29 — 🔴 the reverse direction: it must NOT become fail-closed.
drill "D-86 never fails closed on disconnect" "$PROXY_DIR" "$PROXY_SRC" \
  "TestNeverFailsClosedOnDisconnect" \
  's = s.replace("\tif !g.store.Synced() {\n\t\treturn mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Stale: true}\n\t}", "\tif !g.store.Synced() {\n\t\treturn mcpwire.Decision{Verdict: mcpwire.VerdictDeny, Stale: true}\n\t}")'

# D-92 — one evaluator, shared by the console preview and the live hook.
drill "D-92 console and hook share one evaluator" "$PROXY_DIR" "$PROXY_SRC" \
  "TestConsolePreviewAndHookShareTheEvaluator" \
  's = s.replace("\td := EvaluateDelegation(snap.Delegation, g.catalog.GrantedSlugs(ctx, orgID, seatID), req)", "\td := mcpwire.Decision{Verdict: mcpwire.VerdictAllow}")'

echo
echo "-- aikey-cli/src/mcp_guard.rs"

# D-91 — install MERGES; a third party's PreToolUse entry must survive.
drill_rust "D-91 install preserves a third-party hook" "mcp_guard::tests::install_preserves_a_third_party_hook" \
  's = s.replace("    let existing = list.iter().position(is_ours);", "    list.clear();\n    let existing: Option<usize> = None;")'

# D-91 — uninstall removes OURS only, never the whole container.
drill_rust "D-91 uninstall removes only ours" "mcp_guard::tests::uninstall_removes_only_ours" \
  's = s.replace("    list.retain(|g| !is_ours(g));", "    list.clear();")'

# D-91 — the round trip must leave no residue.
drill_rust "D-91 round trip leaves no residue" "mcp_guard::tests::install_then_uninstall_restores_the_document" \
  's = s.replace("    if list.is_empty() {", "    if false {")'

# D-91 — a second install must refresh in place, never duplicate.
drill_rust "D-91 install is idempotent" "mcp_guard::tests::install_is_idempotent_and_refreshes_a_moved_binary" \
  's = s.replace("    let existing = list.iter().position(is_ours);", "    let existing: Option<usize> = None;")'

# D-93 — refuse a shape we do not understand rather than overwrite it.
drill_rust "D-93 refuses a foreign shape" "mcp_guard::tests::install_refuses_a_shape_it_does_not_understand" \
  's = s.replace("    if !hooks.is_object() {\n        return GuardAction::RefusedForeignShape;\n    }", "    if !hooks.is_object() {\n        *hooks = serde_json::json!({});\n    }")'

# D-94 — the same tool has two names.
drill_rust "D-94 both spawn tool names (via the adapter)" \
  "mcp_guard::tests::both_spawn_tool_names_are_recognised" \
  's = s.replace("tool == \"Agent\" || tool == \"Task\"", "tool == \"Agent\"")' \
  "$CLI_HARNESS"

# D-95 — the main agent is field ABSENCE, not an empty string.
drill_rust "D-95 absence is not an empty agent_id (via the adapter)" \
  "mcp_guard::tests::depth_distinguishes_absence_from_an_empty_agent_id" \
  's = s.replace("is_main_actor: evt.agent_id.is_none(),", "is_main_actor: evt.agent_id.as_deref().unwrap_or(\"\").is_empty(),")' \
  "$CLI_HARNESS"

# R66 / I37 — the reply must have nowhere to put a rewritten input.
#
# 🔴 The mutation ALSO fills the new field in at the construction site. The first
# version only added the field, and the drill went red because the code no longer
# COMPILED — which proves the compiler works, not that the fence does. A drill
# that reports RED for the wrong reason is the same class of lie as one that
# reports GREEN for the wrong reason (repo rule R43: a mutation must actually
# reach the assertion).
drill_rust "R66 reply cannot rewrite input" "mcp_guard::tests::the_reply_has_nowhere_to_put_a_rewritten_input" \
  's = s.replace("    pub permission_decision_reason: Option<String>,\n}", "    pub permission_decision_reason: Option<String>,\n    #[serde(rename = \"updatedInput\", skip_serializing_if = \"Option::is_none\")]\n    pub updated_input: Option<String>,\n}").replace("            permission_decision_reason: if deny && !d.reason.is_empty() {\n                Some(d.reason.clone())\n            } else {\n                None\n            },", "            permission_decision_reason: if deny && !d.reason.is_empty() {\n                Some(d.reason.clone())\n            } else {\n                None\n            },\n            updated_input: None,")'

# Narrowing must not interrupt the developer.
drill_rust "narrow renders as allow" "mcp_guard::tests::narrow_allows_and_deny_carries_its_reason" \
  's = s.replace("    let deny = d.verdict == \"deny\";", "    let deny = d.verdict == \"deny\" || d.verdict == \"narrow\";")'

# A vendor field we have never seen must not break decoding.
drill_rust "unknown vendor fields tolerated (via the adapter)" \
  "mcp_guard::tests::unknown_event_fields_are_tolerated" \
  's = s.replace("#[derive(Debug, Deserialize, Default)]\nstruct ClaudeHookEvent {", "#[derive(Debug, Deserialize, Default)]\n#[serde(deny_unknown_fields)]\nstruct ClaudeHookEvent {")' \
  "$CLI_HARNESS"

# A newer CLI against an older gateway must be NAMED as that, not as a 401.
drill_rust "old gateway is named as such" "mcp_guard::tests::an_old_gateway_is_named_as_an_old_gateway" \
  's = s.replace("    if data_plane_shape {", "    if false {")'

# Cross-language contract: renaming one side must go red.
drill_rust "cross-language contract holds" "mcp_guard::tests::the_gateway_contract_is_the_one_the_proxy_serves" \
  's = s.replace("const FIELD_AGENT_TYPE: &str = \"agent_type\";", "const FIELD_AGENT_TYPE: &str = \"agentType\";")'

echo
echo "-- aikey-control-master (the producer)"

# 🔴 D-27 — an unconfigured org must stay pass-through.
drill_ctl "D-27 unconfigured org stays pass-through" "$CTL_SRC" \
  "TestUnconfiguredOrgProducesAPassThroughPolicy" \
  's = s.replace("\tif doc == \"\" {\n\t\treturn mcpwire.DelegationPolicy{}, \"\", nil\n\t}", "\tif doc == \"\" {\n\t\treturn mcpwire.DelegationPolicy{Tiers: []mcpwire.DelegationTier{{Name: \"default\", AgentTypes: []string{\"*\"}, ToolsetSlugs: []string{}}}}, \"\", nil\n\t}")'

# 🔴 A malformed document must not take the whole policy rail down.
drill_ctl "malformed document does not fail the rail" "$CTL_SRC" \
  "TestAMalformedDocumentPassesThroughAndSaysSo" \
  's = s.replace("\t\treturn mcpwire.DelegationPolicy{}, fmt.Sprintf(", "\t\treturn mcpwire.DelegationPolicy{}, \"\", fmt.Errorf(")'

# An unknown org is a state, not an error.
drill_ctl "unknown org is not an error" "$CTL_SRC" \
  "TestUnknownOrgIsPassThroughNotAnError" \
  's = s.replace("\t\treturn mcpwire.DelegationPolicy{}, \"\", nil\n\t}\n\tif qErr != nil {", "\t\treturn mcpwire.DelegationPolicy{}, \"\", fmt.Errorf(\"no org\")\n\t}\n\tif qErr != nil {")'

# Two encodings of one state.
drill_ctl "empty list stores as the empty value" "$CTL_SRC" \
  "TestAnEmptyTierListIsStoredAsTheEmptyValue" \
  's = s.replace("\tif len(pol.Tiers) == 0 {\n\t\tdoc = []byte(\"\")\n\t}", "")'

# A write to an org that is not there must not report success.
drill_ctl "absent org write is reported" "$CTL_SRC" \
  "TestWritingToAnAbsentOrgIsReported" \
  's = s.replace("\tif err == nil && n == 0 {", "\tif false && err == nil && n == 0 {")'

# 🔴 The whole of 15.2: the rail must actually carry the tiers.
drill_ctl "the policy rail carries the tiers" "$CTL_STORE" \
  "TestBuildPolicyCarriesTheDelegationTiers" \
  's = s.replace("\tif len(delegation.Tiers) > 0 || delegation.DefaultAllow {", "\tif false {")'

# 🔴 An unconfigured org must not claim it chose deny-by-default.
drill_ctl "unconfigured org sends no delegation key" "$CTL_STORE" \
  "TestAnUnconfiguredOrgSendsNoDelegationKey" \
  's = s.replace("\tif len(delegation.Tiers) > 0 || delegation.DefaultAllow {", "\tif true {")'

# MaxDepth=0 is how an administrator forbids delegation; it must be accepted.
drill_ctl "MaxDepth 0 is accepted" "$CTL_SRC" \
  "TestValidationAcceptsMaxDepthZero" \
  's = s.replace("\t\tif t.MaxDepth != nil && *t.MaxDepth < 0 {", "\t\tif t.MaxDepth != nil && *t.MaxDepth <= 0 {")'

# A refused document must change nothing.
drill_ctl "a refused document changes nothing" "$CTL_SRC" \
  "TestARejectedDocumentChangesNothing" \
  's = s.replace("\tif msg := validateDelegation(req.Delegation); msg != \"\" {\n\t\tshared.Error(w, http.StatusBadRequest, \"MCP_INVALID_DELEGATION\", msg)\n\t\treturn\n\t}\n\tif err := h.store.SetDelegationPolicy(r.Context(), orgID, req.Delegation); err != nil {\n\t\th.fail(w, r, \"write delegation tiers\", err)\n\t\treturn\n\t}", "\tif err := h.store.SetDelegationPolicy(r.Context(), orgID, req.Delegation); err != nil {\n\t\th.fail(w, r, \"write delegation tiers\", err)\n\t\treturn\n\t}\n\tif msg := validateDelegation(req.Delegation); msg != \"\" {\n\t\tshared.Error(w, http.StatusBadRequest, \"MCP_INVALID_DELEGATION\", msg)\n\t\treturn\n\t}")'

# Saving must move the delivery cursor, or no machine ever applies the rule.
drill_ctl "saving bumps the delivery version" "$CTL_SRC" \
  "TestSavingTiersBumpsTheDeliveryVersion" \
  's = s.replace("\th.bumpAndLog(r, orgID, \"delegation\")\n", "")'

echo
echo "-- P15 · K4 harness adaptation (15.D) ------------------------------------"

# 🔴 This layer's failure modes are both SILENT: a dispatch that stops being a
# table (the second harness gets added in two places, one is forgotten), and a
# parse that stops being lenient (the vendor adds a field and every developer's
# sub-agents stop at once).

drill_rust "D-136 an unknown harness resolves to nothing" \
  "mcp_harness::tests::the_registry_dispatches_by_name_and_refuses_what_it_does_not_know" \
  's = s.replace("REGISTRY.iter().copied().find(|a| a.name() == name)", "REGISTRY.iter().copied().find(|a| a.name() == name).or(Some(REGISTRY[0]))")' \
  "$CLI_HARNESS"

drill_rust "D-137 only a measured harness is claimed" \
  "mcp_harness::tests::exactly_one_harness_is_claimed" \
  's = s.replace("= &[&ClaudeCode];", "= &[&ClaudeCode, &ClaudeCode];")' \
  "$CLI_HARNESS"

drill_rust "D-138 both spawn tool names are recognised" \
  "mcp_harness::tests::both_spawn_tool_names_are_recognised" \
  's = s.replace("tool == \"Agent\" || tool == \"Task\"", "tool == \"Agent\"")' \
  "$CLI_HARNESS"

drill_rust "D-139 the parse stays lenient" \
  "mcp_harness::tests::an_unknown_field_does_not_break_the_parse" \
  's = s.replace("#[derive(Debug, Deserialize, Default)]\nstruct ClaudeHookEvent {", "#[derive(Debug, Deserialize, Default)]\n#[serde(deny_unknown_fields)]\nstruct ClaudeHookEvent {")' \
  "$CLI_HARNESS"

drill_rust "D-140 a defaulted field is not silent" \
  "mcp_harness::tests::a_missing_subagent_type_defaults_and_warns" \
  's = s.replace("if agent_type.is_empty() {", "if false {")' \
  "$CLI_HARNESS"

drill_rust "D-141 main actor is field ABSENCE" \
  "mcp_harness::tests::main_actor_is_field_absence_not_an_empty_string" \
  's = s.replace("is_main_actor: evt.agent_id.is_none(),", "is_main_actor: evt.agent_id.as_deref().unwrap_or(\"\").is_empty(),")' \
  "$CLI_HARNESS"

# 🔴 Proves the INSTALLER really reads the harness facts from the adapter rather
# than from a second copy: changing the adapter's answer must move what the
# reply and the settings entry say.
drill_rust "D-142 the harness facts have one source" \
  "mcp_guard::tests::the_reply_names_the_event_we_registered_for" \
  's = s.replace("\"PreToolUse\"", "\"PreToolUseX\"")' \
  "$CLI_HARNESS"

echo
echo "-- P15 · 15.12/15.13 the decision is recorded ----------------------------"

# 🔴 Until 2026-09-03 the gate decided, answered and left NO trace: five of the
# six events had zero call sites. A denial, a narrowing and a fail-open were
# indistinguishable from each other and from a gate that was not installed.

drill "D-147 every decision is recorded" "$PROXY_DIR" "$ADMIN_SRC" \
  "TestEveryDelegationDecisionIsRecorded" \
  's = s.replace("\tif name, ok := mcpwire.EventForVerdict[d.Verdict]; ok {", "\tif name, ok := mcpwire.EventForVerdict[d.Verdict]; ok && false {")'

drill "D-148 narrow is not folded into allowed" "$PROXY_DIR" "$ADMIN_SRC" \
  "TestEveryDelegationDecisionIsRecorded" \
  's = s.replace("if name, ok := mcpwire.EventForVerdict[d.Verdict]; ok {", "name, ok := mcpwire.EventDelegationAllowed, true\n\tif ok {")'

# 🔴 The D-29 bargain: failing open is paid for with the WARN. Without it a
# gateway deciding from a month-old snapshot looks exactly like a healthy one.
drill "D-149 a stale fail-open still warns" "$PROXY_DIR" "$ADMIN_SRC" \
  "TestEveryDelegationDecisionIsRecorded" \
  's = s.replace("\tif d.Stale {", "\tif false {")'

echo
echo "-- P15 · 15.F3 nothing of ours leaves for a backend ----------------------"

drill "D-150 X-Aikey-* never reaches a backend" "$PROXY_DIR" "$MCP_UPSTREAM" \
  "TestOutbound_NoTraceHeadersToUpstream" \
  's = s.replace("strings.HasPrefix(lower, \"x-aikey-\") || outboundBannedHeaders[lower]", "false")'

drill "D-151 trace context never reaches a backend" "$PROXY_DIR" "$MCP_UPSTREAM" \
  "TestOutbound_NoTraceHeadersToUpstream" \
  's = s.replace("\"traceparent\": true,", "")'

echo
echo "-- P15 · 15.26 read-only preview -----------------------------------------"

drill_rust "D-143 the preview writes nothing" \
  "mcp_guard::tests::the_preview_writes_nothing" \
  's = s.replace("    let decision = ask_gateway(agent_type, depth);", "    let _ = std::fs::write(\"/tmp/aikey-preview-probe\", \"x\");\n    let decision = ask_gateway(agent_type, depth);")'

drill_rust "D-144 the preview asks the gateway" \
  "mcp_guard::tests::the_preview_asks_the_gateway_rather_than_deciding" \
  's = s.replace("    let decision = ask_gateway(agent_type, depth);", "    let tiers: Vec<String> = Vec::new();\n    let _ = tiers.len();\n    let decision = ask_gateway(agent_type, depth + 0);")'

drill_rust "D-145 an unreachable gateway previews as ALLOWED" \
  "mcp_guard::tests::an_unreachable_gateway_previews_as_allowed_not_as_unknown" \
  's = s.replace("\"verdict\": \"allow\"", "\"verdict\": \"unknown\"")'

drill_rust "D-146 the tools: line is labelled advisory" \
  "mcp_guard::tests::the_whitelist_is_labelled_advisory_where_the_user_can_see_it" \
  's = s.replace("\"advisory\".yellow()", "\"enforced\".yellow()")'

echo
echo "-- P15 · K3 executor attribution (15.F4 / 15.F5) --------------------------"

# 🔴 The whole group guards ONE temptation: actor attribution is ~100%
# unresolved on Claude Code (PRD §0.7), that looks like a bug, and every cheap
# fix for it is a heuristic that would be confidently wrong.

drill "D-128 no other identifier becomes the actor" "$PROXY_DIR" "$MCP_CALLREC" \
  "TestActor_NoHeuristicResolution" \
  's = s.replace("\treturn mcpwire.UnknownActor\n}", "\treturn sessionid.Default().Extract(r, MCPSessionProtocol, \"\")\n}")'

drill "D-129 the actor table takes no fallback" "$PROXY_DIR" "$ACTOR_YAML" \
  "TestActor_NoHeuristicResolution" \
  's = s.replace("common_fallback: []", "common_fallback:\n  - { type: \"header\", name: \"X-Claude-Code-Session-Id\" }")'

# 🔴 This mutation COMPILES — verified by hand before it was written down, and
# that is the entire point. The first draft mutated the SIGNATURE, which broke
# the test file's own call site: the drill went red on a build failure, so the
# assertion it was meant to exercise had never once fired. That is the compiler
# doing the fence's job (R43's mirror), and this repo has now been caught by it
# twice. Returning the app slug needs no signature change, builds cleanly, and
# is the heuristic somebody would actually reach for.
drill "D-130 the extractor touches nothing but the logger" "$PROXY_DIR" "$MCP_CALLREC" \
  "TestActor_NoHeuristicResolution" \
  's = s.replace("\treturn mcpwire.UnknownActor\n}", "\treturn h.appSlugFor(r)\n}")'

drill "D-131 the unresolved case is counted" "$PROXY_DIR" "$MCP_CALLREC" \
  "TestActorUnresolvedIsCountedNotSwallowed" \
  's = s.replace("mcpwire.EventActorUnresolved)", "\"proxy.mcp.actor_unresolved\")")'

# 🔴 The wire-parity fence ENUMERATES the fields it checks, so a new field is
# not covered until somebody adds it — the register-rots-in-the-safe-direction
# shape. This drill is what proves actor_id actually got added to the list.
drill_ctl "D-135 the wire parity fence covers actor_id" "$CTL_CALLS" \
  "TestCallRecordWireShapeMatchesTheProxy" \
  's = s.replace("json:\"actor_id\"", "json:\"actor\"")'

drill_ctl "D-132 the empty column is not a verdict" "$CTL_CALLLOG" \
  "TestActor_UnknownAndPendingAreDistinct" \
  's = s.replace("\tif stored == \"\" {\n\t\treturn nil\n\t}\n", "")'

drill_ctl "D-133 the JSON carries null, not an absent key" "$CTL_CALLLOG" \
  "TestActor_UnknownAndPendingAreDistinct" \
  's = s.replace("ActorID *string `json:\"actor_id\"`", "ActorID *string `json:\"actor_id,omitempty\"`")'

drill_ctl "D-134 no query coalesces the column away" "$CTL_CALLLOG" \
  "TestActor_UnknownAndPendingAreDistinct" \
  's = s.replace("app_slug, actor_id, origin, status, error_code,\n\t\t       duration_ms, args_digest, manifest_hash, created_at_ms,\n\t\t       CASE", "app_slug, COALESCE(actor_id, \x27unknown-actor\x27), origin, status, error_code,\n\t\t       duration_ms, args_digest, manifest_hash, created_at_ms,\n\t\t       CASE")'


echo
echo "-- P15 · 15.16 delegation-gate activity (is the gate being consulted?)"

# 🔴 The whole group guards ONE temptation: three states look like two. "The node
# did not tell us" and "the node says the gate is unused" send the reader to
# different next steps (upgrade that proxy vs. nothing to do), and every cheap
# simplification collapses them into a confident wrong answer about whether an
# organisation is governed at all.

drill_ctl "D-152 an absent report is not idle" "$CTL_GUARD" \
  "TestGuardAbsentIsNotIdle" \
  's = s.replace("\t\tcase rec.state == nil:\n\t\t\tout.Unreportable++", "\t\tcase rec.state == nil:\n\t\t\tout.Idle++")'

# 🔴 Drilled against pkg/mcpwire, where ParseGuardActivity is DEFINED. The first
# version pointed at the control plane's file, matched nothing, and reported
# NO-OP — the "mutation aimed at the wrong file" trap this repo has hit before.
drill "D-153 an unknown wire value is not idle" "$WIRE_DIR" "$WIRE_SRC" \
  "TestGuardUnrecognisedValueIsNotIdle" \
  's = s.replace("\tdefault:\n\t\treturn \"\", false\n\t}\n}", "\tdefault:\n\t\treturn GuardIdle, true\n\t}\n}")'

# 🔴 The mutation WIDENS the TTL rather than deleting the branch: widening is
# what somebody would actually do ("the number keeps flapping"), and it leaves
# delete-on-read in place so the fence has to catch the SEMANTICS.
#
# 🔴 The first version of the FENCE was vacuous against exactly this: it advanced
# the clock by `guardReportTTL + time.Second`, so widening the constant moved the
# assertion along with it and the drill stayed green. A fence whose yardstick is
# the thing under test measures nothing. The assertions are now absolute.
drill_ctl "D-154 a stale report stops counting" "$CTL_GUARD" \
  "TestGuardStaleReportsExpire" \
  's = s.replace("const guardReportTTL = 5 * time.Minute", "const guardReportTTL = 500 * time.Hour")'

# 🔴 And the OTHER direction: shrinking the TTL would drop every seat that missed
# one poll, and the console would report a governed fleet as ungoverned every
# time somebody shut a laptop lid.
drill_ctl "D-154b a seat that missed one poll still counts" "$CTL_GUARD" \
  "TestGuardStaleReportsExpire" \
  's = s.replace("const guardReportTTL = 5 * time.Minute", "const guardReportTTL = 1 * time.Second")'

drill_ctl "D-155 a poll that said nothing is still recorded" "$CTL_CREDDEL" \
  "TestGuardRailRecordsAPollThatSaidNothing" \
  's = s.replace("\t\tif parsed, ok := mcpwire.ParseGuardActivity(raw); ok {\n\t\t\tstate = &parsed\n\t\t}\n\t}", "\t\tif parsed, ok := mcpwire.ParseGuardActivity(raw); ok {\n\t\t\tstate = &parsed\n\t\t}\n\t} else {\n\t\treturn\n\t}")'

# 🔴 R58 shape. A nil *GuardRegister returns a ZERO summary, so this mutation
# compiles and reads as a tidy-up — and it makes a deployment that measures
# nothing render identically to a fleet in which no gate is ever consulted.
drill_ctl "D-156 nothing measured renders as ABSENT not zero" "$CTL_SRC" \
  "TestDelegationOmitsGuardKeyWhenNothingMeasures" \
  's = s.replace("\tif h.guard != nil {\n\t\tbody[\"guard_activity\"] = h.guard.Summary(orgID)\n\t}", "\tbody[\"guard_activity\"] = h.guard.Summary(orgID)")'

# 🔴 The seat half of the same contract. This is the drift that fails SILENTLY:
# the control plane just counts every seat as "cannot tell". This repo has
# shipped that shape twice (the mcp.json object-vs-array drift), which is why
# the assertion is on what the SERVER received.
drill "D-157 the credential rail reports the gate's state" "$PROXY_DIR" "$SUP_RAIL" \
  "TestCredentialRailCarriesTheGuardActivity" \
  's = s.replace("\tu := masterURL + \"/accounts/me/mcp-credentials?\" +\n\t\turl.Values{mcpwire.GuardActivityParam: {string(guard)}}.Encode()", "\tu := masterURL + \"/accounts/me/mcp-credentials\"\n\t_ = guard")'

# 🚫 "Report only when there is good news" — the specific mutation that would
# make the interesting population (seats with no gate) invisible.
drill "D-158 idle is reported, not only active" "$PROXY_DIR" "$SUP_RAIL" \
  "TestCredentialRailCarriesTheGuardActivity" \
  's = s.replace("url.Values{mcpwire.GuardActivityParam: {string(guard)}}.Encode()", "url.Values{mcpwire.GuardActivityParam: {string(mcpwire.GuardActive)}}.Encode()")'

drill "D-159 a request we cannot parse still proves the hook is installed" "$PROXY_DIR" "$ADMIN_SRC" \
  "TestGuardIsNotedEvenWhenTheRequestCannotBeParsed" \
  's = s.replace("\tif h.MCPGuardSeenFn != nil {\n\t\th.MCPGuardSeenFn()\n\t}\n\tvar body struct {", "\tvar body struct {")'

echo
echo "-- P15 · 15.A2/15.A3 the record must be able to answer the question"

# 🔴 Both of these shipped WRONG first, and neither broke a test — they made an
# ACCEPTANCE CRITERION unrunnable, which is a failure nobody sees until somebody
# tries to sign the feature off.

drill "D-165 narrowing records WHICH toolsets, not how many" "$PROXY_DIR" "$ADMIN_SRC" \
  "TestNarrowingRecordsWhichToolsetsNotHowMany" \
  's = s.replace("\"toolsets\", strings.Join(d.Toolsets, \",\")", "\"toolsets\", len(d.Toolsets)")'

drill "D-166 the record names the identity it decided with" "$PROXY_DIR" "$ADMIN_SRC" \
  "TestDelegationRecordNamesTheIdentityItDecidedWith" \
  's = s.replace("\t\t\t\"org_id\", orgID, \"seat_id\", seatID,\n\t\t\t\"agent_type\", agentType, \"depth\", body.Depth,\n\t\t\t\"verdict\"", "\t\t\t\"agent_type\", agentType, \"depth\", body.Depth,\n\t\t\t\"verdict\"")'

# 🔴 STRUCTURAL: a second resolution cannot be seen in the output because in a
# test both lookups agree. It only diverges on a vault reload, in production,
# silently. The mutation is what somebody would actually write.
drill "D-167 the identity is resolved once, not twice" "$PROXY_DIR" "$ADMIN_SRC" \
  "TestDelegationHandlerDoesNotReResolveTheIdentity" \
  's = s.replace("\td, orgID, seatID := h.MCPDelegationFn(agentType, body.Depth)", "\td, _, _ := h.MCPDelegationFn(agentType, body.Depth)\n\torgID, seatID := h.MCPDelegationIdentityFn()")'

drill "D-168 an unidentifiable node is recorded as empty, not invented" "$PROXY_DIR" "$ADMIN_SRC" \
  "TestUnidentifiedNodeIsRecordedAsEmptyNotInvented" \
  's = s.replace("\td, orgID, seatID := h.MCPDelegationFn(agentType, body.Depth)", "\td, orgID, seatID := h.MCPDelegationFn(agentType, body.Depth)\n\tif seatID == \"\" {\n\t\tseatID = \"unknown-seat\"\n\t}")'

echo
echo "-- bugfix 2026-09-08 · the two defects the live failure-path run found"

# 🔴 Both defects shipped WITH fences in place. Each drill states which route the
# old fence guarded and why the bug was on a different one.

# Defect 1. The old fence exercised the !Synced() path; the bug lives on the
# Synced()==true path (cache restored, never polled).
drill "D-169 never-polled is the stalest state, not the freshest" "$PROXY_DIR" "$MCP_POLICY" \
  "TestNeverPolledIsMaximallyStale" \
  's = s.replace("\tage := s.AgeSeconds()\n\tif age < 0 {\n\t\treturn true // never polled — see the header.\n\t}\n\treturn age > seconds", "\treturn s.AgeSeconds() > seconds")'

# 🔴 And the caller must keep ASKING the right question: reverting Decide to the
# raw comparison reproduces the shipped bug even with StalerThan intact.
drill "D-170 the gate asks StalerThan, not the raw sentinel" "$PROXY_DIR" "$PROXY_SRC" \
  "TestNeverPolledIsMaximallyStale" \
  's = s.replace("\td.Stale = g.store.StalerThan(delegationStaleAfterSeconds)", "\td.Stale = g.store.AgeSeconds() > delegationStaleAfterSeconds")'

# Defect 2. Three fences guarded this distinction and all three stayed green,
# because they watch the evaluator and the model — never the serialised bytes.
drill "D-171 a non-narrowing tier survives as null on the wire" "$WIRE_DIR" "$WIRE_SRC" \
  "TestTierPreservesNilToolsetsOnTheWire" \
  's = s.replace("\t// 🚫 ToolsetSlugs is deliberately NOT defaulted. That is the whole point.", "\tif w.ToolsetSlugs == nil {\n\t\tw.ToolsetSlugs = []string{}\n\t}")'

drill "D-172 removing the marshaller is caught" "$WIRE_DIR" "$WIRE_SRC" \
  "TestTierPreservesNilToolsetsOnTheWire" \
  's = s.replace("func (t DelegationTier) MarshalJSON()", "func (t DelegationTier) marshalJSONDisabled()")'

# 🔴 The producer-side fence: it must go through the REAL writer, or it cannot
# see EnsureEmptyCollections at all — which is how this shipped.
drill_ctl "D-173 the producer's WIRE keeps null (through shared.JSON)" "$CTL_SRC" \
  "TestDelegationWireKeepsNilToolsets" \
  's = s.replace("\tshared.JSON(w, http.StatusOK, body)", "\tfor i := range pol.Tiers {\n\t\tif pol.Tiers[i].ToolsetSlugs == nil {\n\t\t\tpol.Tiers[i].ToolsetSlugs = []string{}\n\t\t}\n\t}\n\tbody[\"delegation\"] = pol\n\tshared.JSON(w, http.StatusOK, body)")'

echo
echo "-- restore integrity"
restore
if cmp -s "$WIRE_SRC" "$BACKUP_DIR/wire.go" && cmp -s "$PROXY_SRC" "$BACKUP_DIR/proxy.go" \
   && cmp -s "$MCP_CALLREC" "$BACKUP_DIR/mcp_callrecord.go" \
   && cmp -s "$ACTOR_YAML" "$BACKUP_DIR/actor.yaml" \
   && cmp -s "$CTL_CALLLOG" "$BACKUP_DIR/ctl_calllog.go" \
   && cmp -s "$CTL_CALLS" "$BACKUP_DIR/ctl_calls.go" \
   && cmp -s "$CLI_HARNESS" "$BACKUP_DIR/cli_harness.rs" \
   && cmp -s "$MCP_UPSTREAM" "$BACKUP_DIR/mcp_upstream.go" \
   && cmp -s "$ADMIN_SRC" "$BACKUP_DIR/admin_handlers.go" \
   && cmp -s "$CTL_GUARD" "$BACKUP_DIR/ctl_guard.go" \
   && cmp -s "$CTL_CREDDEL" "$BACKUP_DIR/ctl_creddel.go" \
   && cmp -s "$SUP_RAIL" "$BACKUP_DIR/sup_rail.go" \
   && cmp -s "$MCP_POLICY" "$BACKUP_DIR/mcp_policy.go"; then
  echo "  OK           sources byte-identical to pre-drill"
else
  echo "  DIRTY        a mutation was left behind — inspect the working tree NOW"
  FAILED=1
fi

echo
echo "== drills run: $RAN =="
if [ "$FAILED" -ne 0 ]; then
  echo "== RESULT: FAILED — at least one fence did not catch its own defect =="
  exit 1
fi
echo "== RESULT: all $RAN fences went red for their own defect =="
