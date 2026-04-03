#!/usr/bin/env bash
# DEPRECATED: Use workflow/CD/installer/local-install.sh or server-install.sh instead.
# This script is kept for backward compatibility and reference.
#
# deploy-production.sh — Cross-platform production deployment for aikey-proxy.
#
# Supports deploying to:
#   - Ubuntu 20.04+ / Debian (systemd)
#   - CentOS 7+ / RHEL / Rocky Linux (systemd)
#   - macOS 12+ (launchd)
#
# Run this script from: macOS or Linux build machines.
# For Windows targets, use deploy-production.ps1 instead.
#
# Usage:
#   ./scripts/deploy-production.sh --host user@host --config /path/to/prod.yaml [--vault /path/to/vault.db] [--yes]
#
# Safety checks enforced:
#   - Requires explicit --config (and optional --vault) paths
#   - Runs unit tests before building
#   - Backs up existing binary + config (keeps last 5)
#   - Health check after restart
#
# Prerequisites (build machine):
#   - Go >= 1.26.1
#   - SSH key-based access to target host

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVICE_NAME="aikey-proxy"

# Linux / macOS install paths.
LINUX_INSTALL_DIR="/opt/aikey-proxy"
LINUX_CONFIG_DIR="/etc/aikey-proxy"
LINUX_LOG_DIR="/var/log/aikey-proxy"
LINUX_BACKUP_DIR="/opt/aikey-proxy/backup"

MACOS_INSTALL_DIR="/usr/local/opt/aikey-proxy"
MACOS_CONFIG_DIR="/etc/aikey-proxy"
MACOS_LOG_DIR="/var/log/aikey-proxy"
MACOS_LAUNCHD_LABEL="com.aikeylabs.aikey-proxy"
MACOS_PLIST="/Library/LaunchDaemons/${MACOS_LAUNCHD_LABEL}.plist"

# Parse arguments.
REMOTE_HOST=""
CONFIG_PATH=""
VAULT_PATH=""
SKIP_CONFIRM=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)   REMOTE_HOST="$2"; shift 2 ;;
        --config) CONFIG_PATH="$2"; shift 2 ;;
        --vault)  VAULT_PATH="$2"; shift 2 ;;
        --yes)    SKIP_CONFIRM="true"; shift ;;
        *)        echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

info()  { echo "[INFO]  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
warn()  { echo "[WARN]  $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }
error() { echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; exit 1; }

# --- Validation ---
[ -z "$REMOTE_HOST" ] && error "Production deployment requires --host user@host"
[ -z "$CONFIG_PATH" ] && error "Production deployment requires --config /path/to/config.yaml"
[ ! -f "$CONFIG_PATH" ] && error "Config file not found: ${CONFIG_PATH}"
if [ -n "$VAULT_PATH" ] && [ ! -f "$VAULT_PATH" ]; then
    error "Vault file not found: ${VAULT_PATH}"
fi

# --- Detect remote OS ---
info "Detecting remote OS..."
REMOTE_UNAME=$(ssh "$REMOTE_HOST" 'uname -s' 2>/dev/null) || error "Cannot SSH to ${REMOTE_HOST}"
REMOTE_OS=""
TARGET_ARCH=""
TARGET_GOOS=""
TARGET_GOARCH=""

case "$REMOTE_UNAME" in
    Linux)
        REMOTE_OS="linux"
        # Detect distro family.
        REMOTE_DISTRO=$(ssh "$REMOTE_HOST" \
            'source /etc/os-release 2>/dev/null && echo $ID_LIKE $ID' 2>/dev/null || echo "linux")
        if echo "$REMOTE_DISTRO" | grep -qiE 'rhel|centos|fedora|rocky|almalinux'; then
            REMOTE_OS="centos"
        elif echo "$REMOTE_DISTRO" | grep -qiE 'debian|ubuntu'; then
            REMOTE_OS="ubuntu"
        fi
        TARGET_ARCH=$(ssh "$REMOTE_HOST" 'uname -m' 2>/dev/null || echo "x86_64")
        TARGET_GOOS="linux"
        case "$TARGET_ARCH" in
            aarch64|arm64) TARGET_GOARCH="arm64" ;;
            *)             TARGET_GOARCH="amd64" ;;
        esac
        ;;
    Darwin)
        REMOTE_OS="macos"
        TARGET_ARCH=$(ssh "$REMOTE_HOST" 'uname -m' 2>/dev/null || echo "arm64")
        TARGET_GOOS="darwin"
        TARGET_GOARCH="arm64"
        if [ "$TARGET_ARCH" = "x86_64" ]; then TARGET_GOARCH="amd64"; fi
        ;;
    *)
        error "Unsupported remote OS: ${REMOTE_UNAME}. For Windows, use deploy-production.ps1"
        ;;
esac

info "Remote OS: ${REMOTE_OS} (${TARGET_GOOS}/${TARGET_GOARCH})"

# --- Confirmation ---
if [ -z "$SKIP_CONFIRM" ]; then
    echo ""
    echo "=== PRODUCTION DEPLOYMENT ==="
    echo "  Target:  ${REMOTE_HOST}"
    echo "  OS:      ${REMOTE_OS} (${TARGET_GOOS}/${TARGET_GOARCH})"
    echo "  Config:  ${CONFIG_PATH}"
    echo "  Vault:   ${VAULT_PATH:-<not provided, using existing>}"
    echo ""
    read -rp "Proceed? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
fi

# --- 1. Run tests ---
info "Running tests..."
cd "$PROJECT_DIR"
go test -race ./internal/... || error "Tests failed. Aborting."
info "All tests passed."

# --- 2. Build release binary ---
VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")
BINARY_NAME="${SERVICE_NAME}-${TARGET_GOOS}-${TARGET_GOARCH}"
info "Building ${BINARY_NAME} (version: ${VERSION})..."
GOOS="$TARGET_GOOS" GOARCH="$TARGET_GOARCH" go build \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "bin/${BINARY_NAME}" \
    ./cmd/aikey-proxy
info "Binary built: bin/${BINARY_NAME}"

# --- 3. Upload artifacts ---
info "Uploading to ${REMOTE_HOST}..."
scp "bin/${BINARY_NAME}" "${REMOTE_HOST}:/tmp/${SERVICE_NAME}-new"
scp "$CONFIG_PATH" "${REMOTE_HOST}:/tmp/aikey-proxy-prod.yaml"
if [ -n "$VAULT_PATH" ]; then
    scp "$VAULT_PATH" "${REMOTE_HOST}:/tmp/vault.db"
fi

# --- 4. Deploy: Linux (Ubuntu / CentOS) ---
deploy_linux() {
    local os_type="$1"   # "ubuntu" or "centos"
    local install_dir="$LINUX_INSTALL_DIR"
    local config_dir="$LINUX_CONFIG_DIR"
    local log_dir="$LINUX_LOG_DIR"
    local backup_dir="$LINUX_BACKUP_DIR"

    ssh "$REMOTE_HOST" bash <<REMOTE
set -euo pipefail
info()  { echo "[INFO]  \$(date '+%Y-%m-%d %H:%M:%S') \$*"; }
warn()  { echo "[WARN]  \$(date '+%Y-%m-%d %H:%M:%S') \$*" >&2; }

# Create directories.
sudo mkdir -p ${install_dir} ${config_dir} ${log_dir} ${backup_dir}

# Create service user if needed.
if ! id -u aikey &>/dev/null; then
    if [ "${os_type}" = "ubuntu" ]; then
        sudo adduser --system --no-create-home --shell /usr/sbin/nologin --group aikey
    else
        # CentOS / RHEL / Rocky
        sudo useradd --system --no-create-home --shell /sbin/nologin aikey 2>/dev/null || true
    fi
    info "Created system user: aikey"
fi

# Backup existing files (keep last 5).
TS=\$(date '+%Y%m%d_%H%M%S')
[ -f ${install_dir}/${SERVICE_NAME} ] && \
    sudo cp ${install_dir}/${SERVICE_NAME} ${backup_dir}/${SERVICE_NAME}.\${TS}
[ -f ${config_dir}/aikey-proxy.yaml ] && \
    sudo cp ${config_dir}/aikey-proxy.yaml ${backup_dir}/aikey-proxy.yaml.\${TS}
ls -t ${backup_dir}/${SERVICE_NAME}.* 2>/dev/null | tail -n +6 | xargs -r sudo rm -f
ls -t ${backup_dir}/aikey-proxy.yaml.* 2>/dev/null | tail -n +6 | xargs -r sudo rm -f

# Install binary.
sudo mv /tmp/${SERVICE_NAME}-new ${install_dir}/${SERVICE_NAME}
sudo chmod 755 ${install_dir}/${SERVICE_NAME}
sudo chown root:root ${install_dir}/${SERVICE_NAME}

# Install config.
sudo mv /tmp/aikey-proxy-prod.yaml ${config_dir}/aikey-proxy.yaml
sudo chmod 640 ${config_dir}/aikey-proxy.yaml
sudo chown root:aikey ${config_dir}/aikey-proxy.yaml

# Install vault if provided.
if [ -f /tmp/vault.db ]; then
    VAULT_HOME=\$(getent passwd aikey | cut -d: -f6 2>/dev/null || echo "/home/aikey")
    VAULT_DEST="${config_dir}/vault.db"
    sudo mv /tmp/vault.db "\$VAULT_DEST"
    sudo chmod 600 "\$VAULT_DEST"
    sudo chown aikey:aikey "\$VAULT_DEST"
    info "Vault installed: \$VAULT_DEST"
fi

# Create env file if missing.
if [ ! -f ${config_dir}/env ]; then
    echo "AIKEY_MASTER_PASSWORD=" | sudo tee ${config_dir}/env > /dev/null
    sudo chmod 600 ${config_dir}/env
    sudo chown root:aikey ${config_dir}/env
    warn "IMPORTANT: Set master password in ${config_dir}/env before starting the service."
fi

# Install systemd unit.
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<'UNIT'
[Unit]
Description=AiKey Local Proxy (Production)
Documentation=https://github.com/AiKeyLabs/aikey-proxy
After=network.target

[Service]
Type=simple
User=aikey
Group=aikey
ExecStart=${install_dir}/${SERVICE_NAME} --config ${config_dir}/aikey-proxy.yaml
EnvironmentFile=-${config_dir}/env
Restart=always
RestartSec=5
LimitNOFILE=65536
StandardOutput=append:${log_dir}/proxy.log
StandardError=append:${log_dir}/error.log
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${log_dir}
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}

# Restart or start service.
if sudo systemctl is-active --quiet ${SERVICE_NAME}; then
    info "Restarting ${SERVICE_NAME}..."
    sudo systemctl restart ${SERVICE_NAME}
else
    info "Starting ${SERVICE_NAME}..."
    sudo systemctl start ${SERVICE_NAME}
fi

# Health check.
sleep 2
PORT=\$(grep -oP 'port:\s*\K[0-9]+' ${config_dir}/aikey-proxy.yaml 2>/dev/null || echo "27200")
HOST=\$(grep -oP 'host:\s*"\K[^"]+' ${config_dir}/aikey-proxy.yaml 2>/dev/null || echo "127.0.0.1")
if curl -sf "http://\${HOST}:\${PORT}/health" >/dev/null 2>&1; then
    info "Health check passed: http://\${HOST}:\${PORT}/health"
else
    warn "Health check failed! Run: sudo journalctl -u ${SERVICE_NAME} -n 50"
fi
REMOTE
}

# --- 5. Deploy: macOS (launchd) ---
deploy_macos() {
    local install_dir="$MACOS_INSTALL_DIR"
    local config_dir="$MACOS_CONFIG_DIR"
    local log_dir="$MACOS_LOG_DIR"
    local plist="$MACOS_PLIST"
    local label="$MACOS_LAUNCHD_LABEL"

    ssh "$REMOTE_HOST" bash <<REMOTE
set -euo pipefail
info()  { echo "[INFO]  \$(date '+%Y-%m-%d %H:%M:%S') \$*"; }
warn()  { echo "[WARN]  \$(date '+%Y-%m-%d %H:%M:%S') \$*" >&2; }

sudo mkdir -p ${install_dir} ${config_dir} ${log_dir}

# Create dedicated user (_aikey) using macOS dscl.
if ! id _aikey &>/dev/null; then
    # Find unused UID in system range (< 500).
    MAX_UID=\$(dscl . -list /Users UniqueID | awk '{print \$2}' | sort -n | tail -1)
    NEW_UID=\$(( MAX_UID + 1 ))
    sudo dscl . -create /Users/_aikey
    sudo dscl . -create /Users/_aikey UserShell /usr/bin/false
    sudo dscl . -create /Users/_aikey RealName "AiKey Proxy"
    sudo dscl . -create /Users/_aikey UniqueID \$NEW_UID
    sudo dscl . -create /Users/_aikey PrimaryGroupID 20
    sudo dscl . -create /Users/_aikey NFSHomeDirectory /var/empty
    info "Created system user: _aikey (uid=\$NEW_UID)"
fi

# Install binary.
sudo cp /tmp/${SERVICE_NAME}-new ${install_dir}/${SERVICE_NAME}
sudo chmod 755 ${install_dir}/${SERVICE_NAME}
sudo chown root:wheel ${install_dir}/${SERVICE_NAME}

# Install config.
sudo mv /tmp/aikey-proxy-prod.yaml ${config_dir}/aikey-proxy.yaml
sudo chmod 640 ${config_dir}/aikey-proxy.yaml
sudo chown root:_aikey ${config_dir}/aikey-proxy.yaml 2>/dev/null || \
    sudo chown root:staff ${config_dir}/aikey-proxy.yaml

# Install vault if provided.
if [ -f /tmp/vault.db ]; then
    sudo mv /tmp/vault.db ${config_dir}/vault.db
    sudo chmod 600 ${config_dir}/vault.db
    sudo chown _aikey:staff ${config_dir}/vault.db 2>/dev/null || true
    info "Vault installed: ${config_dir}/vault.db"
fi

# Create env file if missing.
if [ ! -f ${config_dir}/env ]; then
    echo "AIKEY_MASTER_PASSWORD=" | sudo tee ${config_dir}/env > /dev/null
    sudo chmod 600 ${config_dir}/env
    warn "IMPORTANT: Set master password in ${config_dir}/env before starting."
fi

# Load env file values for plist (launchd doesn't support EnvironmentFile).
VAULT_PW=\$(grep '^AIKEY_MASTER_PASSWORD=' ${config_dir}/env 2>/dev/null | cut -d= -f2- || echo "")

# Install launchd plist.
sudo tee ${plist} > /dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${install_dir}/${SERVICE_NAME}</string>
        <string>--config</string>
        <string>${config_dir}/aikey-proxy.yaml</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>AIKEY_MASTER_PASSWORD</key>
        <string>\${VAULT_PW}</string>
    </dict>
    <key>UserName</key>
    <string>_aikey</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${log_dir}/proxy.log</string>
    <key>StandardErrorPath</key>
    <string>${log_dir}/error.log</string>
</dict>
</plist>
PLIST

sudo chmod 644 ${plist}

# Restart or start launchd service.
if sudo launchctl list "${label}" &>/dev/null; then
    info "Reloading ${label}..."
    sudo launchctl unload ${plist} 2>/dev/null || true
fi
info "Loading ${label}..."
sudo launchctl load -w ${plist}

# Health check.
sleep 2
PORT=\$(grep -oP 'port:\s*\K[0-9]+' ${config_dir}/aikey-proxy.yaml 2>/dev/null || echo "27200")
HOST=\$(grep -oP 'host:\s*"\K[^"]+' ${config_dir}/aikey-proxy.yaml 2>/dev/null || echo "127.0.0.1")
if curl -sf "http://\${HOST}:\${PORT}/health" >/dev/null 2>&1; then
    info "Health check passed: http://\${HOST}:\${PORT}/health"
else
    warn "Health check failed! Check logs: tail -f ${log_dir}/error.log"
fi
REMOTE
}

# --- Dispatch ---
case "$REMOTE_OS" in
    ubuntu)  info "Deploying to Ubuntu/Debian..."; deploy_linux "ubuntu" ;;
    centos)  info "Deploying to CentOS/RHEL/Rocky..."; deploy_linux "centos" ;;
    linux)   info "Deploying to Linux (generic)..."; deploy_linux "centos" ;;
    macos)   info "Deploying to macOS..."; deploy_macos ;;
esac

info "Production deployment finished successfully."
