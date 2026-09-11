#!/usr/bin/env bash
# siblings_test.sh — hermetic test for scripts/ci/siblings.sh (make test-ci-scripts).
#
# Builds throwaway git histories shaped like this org's release branches and
# asserts which release line a commit resolves to. The case that matters most is
# the one the old hard-coded list got wrong: a push to a branch cut from
# develop-v1.0.6 must not resolve to develop-v1.0.5. And a release line that did
# not exist when this was written (develop-v1.0.8) must be picked up without any
# edit.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SIB="${HERE}/siblings.sh"
# Invoked through `bash`, never executed directly: the first CI run after #50 died
# with "Permission denied" because the file was committed 100644 (this repo has
# core.fileMode=false), and local runs passed only because the working copy was +x.
sib() { bash "$SIB" "$@"; }
ROOT="$(cd "${HERE}/../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fails=0
ok()  { printf '  ok    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; fails=$((fails + 1)); }
expect() { # name want got
    if [ "$3" = "$2" ]; then ok "$1 → $3"; else bad "$1: want '$2', got '$3'"; fi
}
g() { git -c user.name=ci -c user.email=ci@example.invalid -c init.defaultBranch=main "$@"; }
commit() { g -C "$1" commit -q --allow-empty -m "$2"; }

# ── repos / modules from go.mod ─────────────────────────────────────────────
cat > "$T/go.mod" <<'MOD'
module example.com/m
replace github.com/AiKeyLabs/pkg/egress => ../pkg/egress
replace github.com/AiKeyLabs/pkg/buildinfo => ../pkg/buildinfo
replace github.com/AiKeyLabs/aikey-auth-broker => ../aikey-auth-broker
replace github.com/aikeylabs/ai-degrade-detector/proxy-plugin/rhythm => ../ai-degrade-detector/proxy-plugin/rhythm
replace github.com/other/notsibling => github.com/other/fork v1.2.3
MOD
expect "repos (fixture)" "ai-degrade-detector aikey-auth-broker pkg" "$(sib repos "$T/go.mod" | tr '\n' ' ' | sed 's/ $//')"
expect "modules pkg (fixture)" "github.com/AiKeyLabs/pkg/buildinfo github.com/AiKeyLabs/pkg/egress" "$(sib modules pkg "$T/go.mod" | tr '\n' ' ' | sed 's/ $//')"
real="$(sib repos "${ROOT}/go.mod" | tr '\n' ' ' | sed 's/ $//')"
[ -n "$real" ] && ok "repos (this module's go.mod) → ${real}" || bad "repos found nothing in ${ROOT}/go.mod"

# ── release-line ────────────────────────────────────────────────────────────
# origin:  main ─ a ─ (develop-v1.0.5) b ─ (develop-v1.0.6) c ─ d ─ (develop-v1.0.7) e
#          v1.0.5 gets its own later commit b2; v1.0.6 gets d; v1.0.7 gets e.
O="$T/origin"; mkdir -p "$O"; g init -q "$O"
commit "$O" a
g -C "$O" branch develop-v1.0.5; g -C "$O" checkout -q develop-v1.0.5; commit "$O" b
g -C "$O" branch develop-v1.0.6; commit "$O" b2
g -C "$O" checkout -q develop-v1.0.6; commit "$O" c
g -C "$O" branch develop-v1.0.7; commit "$O" d
g -C "$O" checkout -q develop-v1.0.7; commit "$O" e
g -C "$O" branch sync/develop-v1.0.5-into-v1.0.6 develop-v1.0.6
g -C "$O" checkout -q main
C="$T/clone"; g clone -q "$O" "$C"

line_at() { # <start-ref> <extra commits>
    g -C "$C" checkout -q --detach "$1"
    for i in $(seq 1 "$2"); do commit "$C" "feature-$i"; done
    (cd "$C" && sib release-line 2>/dev/null)
}
expect "push to a branch cut from develop-v1.0.6"         develop-v1.0.6 "$(line_at origin/develop-v1.0.6 2)"
expect "push to a branch cut from develop-v1.0.5"         develop-v1.0.5 "$(line_at origin/develop-v1.0.5 1)"
expect "push to a branch cut from develop-v1.0.7"         develop-v1.0.7 "$(line_at origin/develop-v1.0.7 3)"
expect "push exactly at the develop-v1.0.6 tip"           develop-v1.0.6 "$(line_at origin/develop-v1.0.6 0)"
expect "sync/ branches are not release lines"             develop-v1.0.6 "$(line_at origin/sync/develop-v1.0.5-into-v1.0.6 1)"

# A pushed feature branch is itself on origin, and it is always the NEAREST fork
# point of its own next commit. Only release branches may be candidates, or every
# push would resolve to its own branch name.
g -C "$O" checkout -q -b fix/some-feature develop-v1.0.6; commit "$O" f1; commit "$O" f2; g -C "$O" checkout -q main
g -C "$C" fetch -q origin
expect "a nearer non-release branch on origin is ignored"  develop-v1.0.6 "$(line_at origin/fix/some-feature 1)"

# A release line created after this test was written: no edit anywhere.
g -C "$O" checkout -q develop-v1.0.7; g -C "$O" branch develop-v1.0.8; g -C "$O" checkout -q develop-v1.0.8; commit "$O" f; g -C "$O" checkout -q main
g -C "$C" fetch -q origin
expect "a new develop-v1.0.8 is picked up without editing anything" develop-v1.0.8 "$(line_at origin/develop-v1.0.8 1)"

# No release refs at all: fail, and say what to fetch.
N="$T/noremote"; g init -q "$N"; commit "$N" x
if out="$(cd "$N" && sib release-line 2>&1)"; then bad "no release refs: exited 0 with '$out'"
else case "$out" in *"fetch-depth: 0"*) ok "no release refs → fails and names fetch-depth: 0" ;; *) bad "no release refs: unhelpful message '$out'" ;; esac; fi

[ "$fails" -eq 0 ] && { echo "PASS: siblings.sh"; exit 0; }
echo "FAIL: ${fails} check(s)"; exit 1
