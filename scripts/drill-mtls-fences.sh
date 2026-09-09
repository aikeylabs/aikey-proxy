#!/usr/bin/env bash
# Mutation drill for the mTLS fences (P4 · task 4.8 · D-10 · 2026-09-04).
#
# WHY THIS EXISTS
# ---------------
# Three properties, and the third is the one this feature nearly broke:
#
#   4.F6  mutual TLS must never skip SERVER verification. Skipping it leaves a
#         deployment that proves its own identity to anything that answers the
#         address — the inversion of what the customer bought.
#   4.F7  a client certificate the backend does not trust must not connect.
#   15.F3 (widened) EVERY outbound client strips our internal headers. The
#         original fence named `upstreamHTTPClient` because it was the only one;
#         mTLS adds a client per certificate alias, and a fence that names one
#         client says nothing about the others.
#
# 🚫 No `| head`: SIGPIPE would kill the drill mid-mutation.
# Ruling: tasks.md § A 类阻塞项的裁决 § A-2 (D-10)
# Usage:  make -C aikey-proxy drill-mtls
set -uo pipefail

cd "$(dirname "$0")/.."
PROXY_DIR="$PWD"
CTL_DIR="$PWD/../aikey-control-master/service"

MTLS_SRC="$PROXY_DIR/internal/mcp/mtls.go"
UPSTREAM_SRC="$PROXY_DIR/internal/mcp/upstream.go"
CTL_HANDLER="$CTL_DIR/internal/mcpgateway/handler.go"

BACKUP_DIR="$(mktemp -d -t mtls_drill)"
cp "$MTLS_SRC"     "$BACKUP_DIR/mtls.go"
cp "$UPSTREAM_SRC" "$BACKUP_DIR/upstream.go"
cp "$CTL_HANDLER"  "$BACKUP_DIR/handler.go"

FAILED=0
RAN=0

restore() {
  cp "$BACKUP_DIR/mtls.go"     "$MTLS_SRC"
  cp "$BACKUP_DIR/upstream.go" "$UPSTREAM_SRC"
  cp "$BACKUP_DIR/handler.go"  "$CTL_HANDLER"
}
trap 'restore; rm -rf "$BACKUP_DIR"' EXIT INT TERM

backup_of() {
  case "$1" in
    "$MTLS_SRC")     echo "$BACKUP_DIR/mtls.go" ;;
    "$UPSTREAM_SRC") echo "$BACKUP_DIR/upstream.go" ;;
    "$CTL_HANDLER")  echo "$BACKUP_DIR/handler.go" ;;
  esac
}

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

echo "── mTLS · mutation drill ─────────────────────────────────────────────────"
echo
echo "4.F6 — server verification is never skipped"

drill "M-1 InsecureSkipVerify is refused" "$PROXY_DIR" "$MTLS_SRC" \
  "TestMTLSNeverSkipsServerVerification" \
  's = s.replace("MinVersion: tls.VersionTLS12,", "MinVersion: tls.VersionTLS12,\n\t\t\t\tInsecureSkipVerify: true,")'

drill "M-2 the TLS floor is stated" "$PROXY_DIR" "$MTLS_SRC" \
  "TestMTLSNeverSkipsServerVerification" \
  's = s.replace("MinVersion: tls.VersionTLS12,", "MinVersion: tls.VersionTLS10,")'

echo
echo "4.F7 — an untrusted client certificate cannot connect"

# 🔴 Dropping the certificate makes the handshake fail for BOTH halves, so the
# positive case goes red too — which is the point: the fence's two halves are
# what stop "everything is refused" from passing as "the wrong one is refused".
drill "M-3 the certificate is actually presented" "$PROXY_DIR" "$MTLS_SRC" \
  "TestMTLSWrongClientCertificateCannotConnect" \
  's = s.replace("Certificates: []tls.Certificate{pair},", "Certificates: nil,")'

drill "M-4 mTLS backends do not fall back to the plain client" "$PROXY_DIR" "$UPSTREAM_SRC" \
  "TestMTLSWrongClientCertificateCannotConnect" \
  's = s.replace("if b.MTLSCertAlias == \"\" {", "if true {")'

echo
echo "15.F3 widened — every outbound client strips our headers"

drill "M-5 a new client cannot skip the stripper" "$PROXY_DIR" "$MTLS_SRC" \
  "TestEveryOutboundClientStripsHeaders" \
  's = s.replace("Transport: &headerStripper{next: &http.Transport{", "Transport: (&struct{ http.RoundTripper }{&http.Transport{")'

drill "M-6 unusable material is refused, not downgraded" "$PROXY_DIR" "$MTLS_SRC" \
  "TestMTLSMaterialThatDoesNotParseIsRefusedNotDowngraded" \
  's = s.replace("return nil, fmt.Errorf(\"the client certificate stored under alias %q is not a usable \"+", "return upstreamHTTPClient, nil\n\t\tif false { return nil, fmt.Errorf(\"the client certificate stored under alias %q is not a usable \"+")'

echo
echo "control plane — a keypair is checked at the door"

drill "M-7 an mtls secret must be a real keypair" "$CTL_DIR" "$CTL_HANDLER" \
  "TestMTLSCredentialValidation" \
  's = s.replace("if req.Kind == CredentialMTLS {", "if false {")'

echo
verify_pristine() {
  local bad=0
  for pair in "$MTLS_SRC:mtls.go" "$UPSTREAM_SRC:upstream.go" "$CTL_HANDLER:handler.go"; do
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
