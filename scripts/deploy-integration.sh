#!/usr/bin/env bash
# deploy-integration.sh — Deploy aikey-proxy to an integration/staging environment.
# Targets Linux amd64 servers. Builds a release binary and sets up systemd service.
#
# Usage:
#   ./scripts/deploy-integration.sh [--host user@host] [--config /path/to/config.yaml]
#
# Prerequisites:
#   - Go >= 1.26.1 (local build machine)
#   - SSH access to target host (if remote)
#   - Target host: Linux amd64, systemd

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVICE_NAME="aikey-proxy"
INSTALL_DIR="/opt/aikey-proxy"
CONFIG_DIR="/etc/aikey-proxy"
LOG_DIR="/var/log/aikey-proxy"

# Parse arguments.
REMOTE_HOST=""
CONFIG_PATH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)   REMOTE_HOST="$2"; shift 2 ;;
        --config) CONFIG_PATH="$2"; shift 2 ;;
        *)        echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*" >&2; }
error() { echo "[ERROR] $*" >&2; exit 1; }

# --- 1. Cross-compile for Linux ---
info "Building aikey-proxy for linux/amd64..."
cd "$PROJECT_DIR"
GOOS=linux GOARCH=amd64 go build \
    -ldflags "-X main.version=$(git describe --tags --always 2>/dev/null || echo 'dev')" \
    -o "bin/${SERVICE_NAME}-linux-amd64" \
    ./cmd/aikey-proxy

BINARY="bin/${SERVICE_NAME}-linux-amd64"
info "Binary built: ${BINARY}"

# --- 2. Generate systemd unit file ---
UNIT_FILE="/tmp/${SERVICE_NAME}.service"
cat > "$UNIT_FILE" <<'UNIT'
[Unit]
Description=AiKey Local Proxy
Documentation=https://github.com/AiKeyLabs/aikey-proxy
After=network.target

[Service]
Type=simple
User=aikey
Group=aikey
ExecStart=/opt/aikey-proxy/aikey-proxy --config /etc/aikey-proxy/aikey-proxy.yaml
EnvironmentFile=-/etc/aikey-proxy/env
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/aikey-proxy
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

info "Generated systemd unit: ${UNIT_FILE}"

# --- 3. Deploy ---
deploy_local() {
    info "Deploying locally (integration)..."

    sudo mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"

    # Create service user if not exists.
    if ! id -u aikey &>/dev/null; then
        sudo useradd --system --no-create-home --shell /usr/sbin/nologin aikey
        info "Created system user: aikey"
    fi

    sudo cp "$BINARY" "${INSTALL_DIR}/${SERVICE_NAME}"
    sudo chmod 755 "${INSTALL_DIR}/${SERVICE_NAME}"

    if [ -n "$CONFIG_PATH" ]; then
        sudo cp "$CONFIG_PATH" "${CONFIG_DIR}/aikey-proxy.yaml"
    elif [ ! -f "${CONFIG_DIR}/aikey-proxy.yaml" ]; then
        sudo cp "${PROJECT_DIR}/aikey-proxy.yaml.example" "${CONFIG_DIR}/aikey-proxy.yaml"
        warn "Using example config. Edit ${CONFIG_DIR}/aikey-proxy.yaml before starting."
    fi

    # Create env file template if not exists.
    if [ ! -f "${CONFIG_DIR}/env" ]; then
        echo "AIKEY_VAULT_PASSWORD=" | sudo tee "${CONFIG_DIR}/env" > /dev/null
        sudo chmod 600 "${CONFIG_DIR}/env"
        warn "Set vault password in ${CONFIG_DIR}/env"
    fi

    sudo cp "$UNIT_FILE" "/etc/systemd/system/${SERVICE_NAME}.service"
    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"

    info "Deployment complete. Start with: sudo systemctl start ${SERVICE_NAME}"
}

deploy_remote() {
    info "Deploying to remote host: ${REMOTE_HOST}..."

    scp "$BINARY" "${REMOTE_HOST}:/tmp/${SERVICE_NAME}"
    scp "$UNIT_FILE" "${REMOTE_HOST}:/tmp/${SERVICE_NAME}.service"

    if [ -n "$CONFIG_PATH" ]; then
        scp "$CONFIG_PATH" "${REMOTE_HOST}:/tmp/aikey-proxy.yaml"
    fi

    ssh "$REMOTE_HOST" bash <<REMOTE
set -euo pipefail
sudo mkdir -p ${INSTALL_DIR} ${CONFIG_DIR} ${LOG_DIR}
id -u aikey &>/dev/null || sudo useradd --system --no-create-home --shell /usr/sbin/nologin aikey
sudo mv /tmp/${SERVICE_NAME} ${INSTALL_DIR}/${SERVICE_NAME}
sudo chmod 755 ${INSTALL_DIR}/${SERVICE_NAME}
if [ -f /tmp/aikey-proxy.yaml ]; then
    sudo mv /tmp/aikey-proxy.yaml ${CONFIG_DIR}/aikey-proxy.yaml
elif [ ! -f ${CONFIG_DIR}/aikey-proxy.yaml ]; then
    echo "WARNING: No config file. Copy one to ${CONFIG_DIR}/aikey-proxy.yaml"
fi
if [ ! -f ${CONFIG_DIR}/env ]; then
    echo "AIKEY_VAULT_PASSWORD=" | sudo tee ${CONFIG_DIR}/env > /dev/null
    sudo chmod 600 ${CONFIG_DIR}/env
fi
sudo mv /tmp/${SERVICE_NAME}.service /etc/systemd/system/${SERVICE_NAME}.service
sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}
echo "[INFO] Deployment complete. Start with: sudo systemctl start ${SERVICE_NAME}"
REMOTE
}

if [ -n "$REMOTE_HOST" ]; then
    deploy_remote
else
    deploy_local
fi

# Cleanup.
rm -f "$UNIT_FILE"
info "Done."
