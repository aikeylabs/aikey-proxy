#!/usr/bin/env bash
# dev-setup.sh — Local development environment setup for aikey-proxy.
# Supports macOS (arm64/amd64) and Windows (via Git Bash / WSL).
#
# Usage:
#   chmod +x scripts/dev-setup.sh
#   ./scripts/dev-setup.sh
#
# Prerequisites:
#   - Go >= 1.26.1 installed and in PATH
#   - AiKey vault (~/.aikey/data/vault.db) created by aikey-cli

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="${PROJECT_DIR}/aikey-proxy.yaml"
EXAMPLE_CONFIG="${PROJECT_DIR}/aikey-proxy.yaml.example"
BIN_DIR="${PROJECT_DIR}/bin"

info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*" >&2; }
error() { echo "[ERROR] $*" >&2; exit 1; }

# --- 1. Check Go installation ---
info "Checking Go installation..."
if ! command -v go &>/dev/null; then
    error "Go is not installed. Please install Go >= 1.26.1 from https://go.dev/dl/"
fi

GO_VERSION=$(go version | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
info "Found ${GO_VERSION}"

# --- 2. Install dependencies ---
info "Downloading Go modules..."
cd "$PROJECT_DIR"
go mod download

# --- 3. Build ---
info "Building aikey-proxy..."
make build
info "Binary built at ${BIN_DIR}/aikey-proxy"

# --- 3a. Install via deploy project (handles PATH + shell registration) ---
DEPLOY_LOCAL="$(cd "${SCRIPT_DIR}/../../deploy/scripts" 2>/dev/null && pwd)/deploy-local.sh"
if [ -f "$DEPLOY_LOCAL" ]; then
    bash "$DEPLOY_LOCAL" "$BIN_DIR"
else
    # Fallback: minimal install without shell registration.
    AIKEY_BIN="${HOME}/.aikey/bin"
    AIKEY_CONFIG="${HOME}/.aikey/config"
    mkdir -p "$AIKEY_BIN" "$AIKEY_CONFIG"
    install -m755 "${BIN_DIR}/aikey-proxy"      "${AIKEY_BIN}/aikey-proxy"
    install -m644 "${BIN_DIR}/aikey-proxy.yaml" "${AIKEY_CONFIG}/aikey-proxy.yaml"
    # macOS: remove provenance xattr and ad-hoc re-sign so Gatekeeper won't SIGKILL.
    if [ "$(uname -s)" = "Darwin" ]; then
        xattr -d com.apple.provenance "${AIKEY_BIN}/aikey-proxy" 2>/dev/null || true
        codesign -fs - "${AIKEY_BIN}/aikey-proxy" 2>/dev/null || true
    fi
    info "Installed (deploy project not found; shell registration skipped)"
fi

# --- 4. Prepare config ---
if [ ! -f "$CONFIG_FILE" ]; then
    info "Copying example config to ${CONFIG_FILE}"
    cp "$EXAMPLE_CONFIG" "$CONFIG_FILE"
    warn "Please edit ${CONFIG_FILE} to configure your virtual keys."
else
    info "Config file already exists: ${CONFIG_FILE}"
fi

# --- 5. Check vault ---
VAULT_PATH="${HOME}/.aikey/data/vault.db"
if [ -f "$VAULT_PATH" ]; then
    info "Vault found: ${VAULT_PATH}"
else
    warn "Vault not found at ${VAULT_PATH}"
    warn "Create one with: aikey-cli vault init"
fi

# --- 6. Install dev tools (optional) ---
if command -v golangci-lint &>/dev/null; then
    info "golangci-lint already installed"
else
    info "Installing golangci-lint..."
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest 2>/dev/null || \
        warn "Failed to install golangci-lint. Install manually: https://golangci-lint.run/usage/install/"
fi

# --- 7. Run tests ---
info "Running tests..."
make test

# --- Done ---
echo ""
info "Development environment ready!"
info ""
info "Proxy auto-starts on first aikey command."
info ""
info "To verify:"
info "  aikey proxy status"
info "  curl http://127.0.0.1:27200/health"
