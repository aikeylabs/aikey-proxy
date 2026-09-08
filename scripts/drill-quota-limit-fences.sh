#!/usr/bin/env bash
# Mutation drill for the quota non-positive-limit fences (2026-09-04).
#
# WHY THIS EXISTS
# ---------------
# A green fence proves nothing until you have watched it go red for the defect it
# claims to guard. Two properties are drilled here, and they sit in two different
# repos because the quota write path and the quota read path are two different
# programs:
#
#   · aikey-proxy       a rule enforcement drops must be NAMED, not swallowed
#   · aikey-control-*   a non-positive limit must be REFUSED on the way in
#
# 🔴 The second one is not only about today's behaviour. It is a tripwire on an
# open window: because zero is refused everywhere, no stored row means anything
# by it, so `limit_amount` can still be given a three-state encoding (absent /
# 0 = none allowed / N) at zero migration cost. That window closes the moment
# anything starts storing a zero. The fence is what makes the closure loud.
#
# FIVE WAYS A DRILL LIES, all guarded against here
#   1. a mutation that matched nothing        → `cmp` makes a NO-OP a failure
#   2. a `-run` selector matching no test     → `go test` reports SUCCESS for an
#      empty selection; classified by requiring a FAIL line for the named test
#   3. a stale build cache answering          → `-count=1`
#   4. a mutation left behind by a crash      → trap on EXIT/INT/TERM
#   5. a poisoned file taken as the baseline  → the backup is made ONCE, before
#      any mutation, and verified byte-identical at the end
#
# 🚫 No `| head` anywhere: SIGPIPE would kill the drill mid-mutation.
#
# Ruling: roadmap20260320/技术实现/阶段8-平台化/MCP网关/openspec/changes/aikey-mcp-gateway/tasks.md
#         § A 类阻塞项的裁决 § A-3
# Usage:  make -C aikey-proxy drill-quota-limits
set -uo pipefail

cd "$(dirname "$0")/.."
PROXY_DIR="$PWD"
CTL_DIR="$PWD/../aikey-control-master/service"

PROXY_SNAP="$PROXY_DIR/internal/quota/snapshot.go"
PROXY_ENFORCE="$PROXY_DIR/internal/quota/enforce.go"
CTL_HANDLER="$CTL_DIR/internal/quota/handler.go"

BACKUP_DIR="$(mktemp -d -t quota_limit_drill)"
cp "$PROXY_SNAP"    "$BACKUP_DIR/snapshot.go"
cp "$PROXY_ENFORCE" "$BACKUP_DIR/enforce.go"
cp "$CTL_HANDLER"   "$BACKUP_DIR/handler.go"

FAILED=0
RAN=0

restore() {
  cp "$BACKUP_DIR/snapshot.go" "$PROXY_SNAP"
  cp "$BACKUP_DIR/enforce.go"  "$PROXY_ENFORCE"
  cp "$BACKUP_DIR/handler.go"  "$CTL_HANDLER"
}
trap 'restore; rm -rf "$BACKUP_DIR"' EXIT INT TERM

backup_of() {
  case "$1" in
    "$PROXY_SNAP")    echo "$BACKUP_DIR/snapshot.go" ;;
    "$PROXY_ENFORCE") echo "$BACKUP_DIR/enforce.go" ;;
    "$CTL_HANDLER")   echo "$BACKUP_DIR/handler.go" ;;
  esac
}

# drill <id> <dir> <file> <test-name> <python-mutation>
#
# 🔴 GOWORK=off for the control module: it is NOT in the workspace, so a run that
# inherits the workspace resolves a different set of sibling modules than the one
# this module actually ships against.
drill() {
  local id="$1" dir="$2" file="$3" test_name="$4" mutation="$5"
  local backup
  backup="$(backup_of "$file")"

  restore
  RAN=$((RAN + 1))

  python3 - "$file" <<PY
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text(encoding="utf-8")
$mutation
p.write_text(s, encoding="utf-8")
PY

  if cmp -s "$file" "$backup"; then
    echo "  NO-OP        $id — mutation matched nothing; this drill proves nothing"
    FAILED=1
    restore
    return
  fi

  local out
  out="$(cd "$dir" && GOWORK=off go test ./... -run "^$test_name\$" -count=1 2>&1)"

  if printf '%s' "$out" | grep -q -- "--- FAIL: $test_name\|^FAIL\|build failed\|cannot use\|undefined:"; then
    echo "  RED          $id"
  elif printf '%s' "$out" | grep -q "no tests to run"; then
    echo "  NO-OP        $id — the selector matched no test (renamed?)"
    FAILED=1
  else
    echo "  STAYED GREEN $id — the fence did not catch its own defect"
    printf '%s' "$out" | tail -15 | sed 's/^/               /'
    FAILED=1
  fi
  restore
}

echo "── quota non-positive limit · mutation drill ──────────────────────────────"
echo
echo "read path (aikey-proxy) — a dropped rule must be named"

drill "Q-1 a non-positive limit is reported" "$PROXY_DIR" "$PROXY_SNAP" \
  "TestUnenforceableRulesAreNamedNotSwallowed" \
  's = s.replace("\t\t\tif r.LimitAmount <= 0 {", "\t\t\tif r.LimitAmount < 0 {")'

drill "Q-2 the report is not silenced wholesale" "$PROXY_DIR" "$PROXY_SNAP" \
  "TestUnenforceableRulesAreNamedNotSwallowed" \
  's = s.replace("func UnenforceableRules(subjects []Subject) []UnenforceableRule {", "func UnenforceableRules(subjects []Subject) []UnenforceableRule {\n\tif true {\n\t\treturn nil\n\t}")'

drill "Q-3 a healthy snapshot stays quiet" "$PROXY_DIR" "$PROXY_SNAP" \
  "TestUnenforceableRulesAreNamedNotSwallowed" \
  's = s.replace("\t\t\tif r.LimitAmount <= 0 {", "\t\t\tif r.LimitAmount <= 1 {")'

# 🔴 The invariant that makes the report trustworthy: reporter and enforcer must
# agree on which rules are dropped. Mutating ONE of them must go red.
drill "Q-4 reporter and enforcer agree" "$PROXY_DIR" "$PROXY_ENFORCE" \
  "TestUnenforceableRulesAreNamedNotSwallowed" \
  's = s.replace("rule.LimitAmount <= 0", "rule.LimitAmount < 0")'

echo
echo "write path (aikey-control-master) — the three-state window stays open"

drill "Q-5 a zero limit is refused" "$CTL_DIR" "$CTL_HANDLER" \
  "TestQuotaLimitZeroIsRefusedSoTheThreeStateWindowStaysOpen" \
  's = s.replace("if rule.LimitAmount <= 0 {", "if rule.LimitAmount < 0 {")'

drill "Q-6 the refusal names the field" "$CTL_DIR" "$CTL_HANDLER" \
  "TestQuotaLimitZeroIsRefusedSoTheThreeStateWindowStaysOpen" \
  's = s.replace("rules[%d].limit_amount must be > 0", "invalid params")'

echo
verify_pristine() {
  local bad=0
  for pair in "$PROXY_SNAP:snapshot.go" "$PROXY_ENFORCE:enforce.go" "$CTL_HANDLER:handler.go"; do
    local f="${pair%%:*}" b="${pair##*:}"
    if ! cmp -s "$f" "$BACKUP_DIR/$b"; then
      echo "  🔴 NOT RESTORED: $f"
      bad=1
    fi
  done
  return $bad
}
if verify_pristine; then
  echo "  source restored byte-identical"
else
  FAILED=1
fi

echo
if [ "$FAILED" -eq 0 ]; then
  echo "── $RAN/$RAN drills RED. Every fence caught its own defect. ───────────────"
else
  echo "── DRILL FAILED — a fence that cannot go red is not a fence."
fi
exit "$FAILED"
