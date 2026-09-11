#!/usr/bin/env bash
# siblings.sh — what CI must check out beside this module, and from which branch.
#
#   scripts/ci/siblings.sh repos [go.mod]            repositories named by go.mod's `=> ../<repo>/…` replaces
#   scripts/ci/siblings.sh modules <repo> [go.mod]   the replaced module paths that live in <repo>
#   scripts/ci/siblings.sh release-line              the release branch HEAD belongs to (develop-v* or main)
#
# 🔴 Why `repos` is derived, not written down
#
# ci.yml used to carry a hand-written repository list beside go.mod. Two lists of
# one fact drift; the job summary that names what AIKEY_CI_TOKEN must read is only
# trustworthy if it comes from the file the compiler reads.
#
# 🔴 Why `release-line` exists (2026-09-11)
#
# The sibling checkout tried `HEAD_REF BASE_REF GITHUB_REF_NAME develop-v1.0.5 main`.
# On a `push` there is no head/base ref, so every feature-branch push fell through
# to the hard-coded develop-v1.0.5 and tested this module against the previous
# release line's siblings (log: `pkg @ develop-v1.0.5` on a develop-v1.0.6 change).
# Replacing the literal with develop-v1.0.6 would go stale again at the next line —
# develop-v1.0.7 already exists. Instead: the release line of a commit is the
# release branch it forked from most recently, i.e. the `origin/develop-v*` or
# `origin/main` whose merge-base with HEAD leaves the FEWEST commits on HEAD's side.
# Ties (a branch cut from another with no commits of its own yet) go to the branch
# that has moved least since the fork, then to the ref name order git lists.
#
# Needs full history for the remote release branches: actions/checkout fetch-depth: 0.
# Regression test: scripts/ci/siblings_test.sh (make test-ci-scripts).
set -euo pipefail

cmd="${1:-}"
[ $# -gt 0 ] && shift

case "$cmd" in
repos)
    gomod="${1:-go.mod}"
    grep -oE '=>[[:space:]]*\.\./[^/[:space:]]+' "$gomod" | sed -E 's#^=>[[:space:]]*\.\./##' | sort -u
    ;;
modules)
    repo="${1:?usage: siblings.sh modules <repo> [go.mod]}"
    gomod="${2:-go.mod}"
    grep -E "=>[[:space:]]*\.\./${repo}(/|[[:space:]]|\$)" "$gomod" \
        | sed -E 's/^[[:space:]]*replace[[:space:]]+//; s/[[:space:]]*=>.*$//' | sort -u
    ;;
release-line)
    best=""; best_ahead=0; best_behind=0
    while IFS= read -r ref; do
        [ -n "$ref" ] || continue
        branch="${ref#refs/remotes/origin/}"
        mb="$(git merge-base HEAD "$ref" 2>/dev/null)" || continue
        ahead="$(git rev-list --count "${mb}..HEAD")"
        behind="$(git rev-list --count "${mb}..${ref}")"
        echo "  ${branch}: HEAD is ${ahead} commit(s) past the fork point; the branch moved ${behind} since" >&2
        if [ -z "$best" ] || [ "$ahead" -lt "$best_ahead" ] \
            || { [ "$ahead" -eq "$best_ahead" ] && [ "$behind" -lt "$best_behind" ]; }; then
            best="$branch"; best_ahead="$ahead"; best_behind="$behind"
        fi
    done < <(git for-each-ref --format='%(refname)' 'refs/remotes/origin/develop-v*' 'refs/remotes/origin/main')
    if [ -z "$best" ]; then
        echo "no origin/develop-v* or origin/main shares history with HEAD. Fetch them (actions/checkout fetch-depth: 0)." >&2
        exit 1
    fi
    printf '%s\n' "$best"
    ;;
*)
    sed -n '2,6p' "$0" >&2
    exit 2
    ;;
esac
