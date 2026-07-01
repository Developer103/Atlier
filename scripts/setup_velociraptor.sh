#!/usr/bin/env bash
# setup_velociraptor.sh — Deploy Velociraptor server on host
# Usage: ./setup_velociraptor.sh [--stop] [--status]
set -euo pipefail

VELO_DIR="/tmp/velociraptor"
VELO_BIN="${VELO_DIR}/velociraptor"
VELO_SERVER_CONFIG="${VELO_DIR}/server.config.yaml"
VELO_CLIENT_CONFIG="${VELO_DIR}/client.config.yaml"
VELO_PID_FILE="${VELO_DIR}/server.pid"
VELO_VERSION="0.77.1"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

do_status() {
    if [[ -f "$VELO_PID_FILE" ]]; then
        pid=$(cat "$VELO_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Velociraptor server is running (PID ${pid})"
            echo "  GUI: https://localhost:8889"
            echo "  API: https://localhost:8001"
            exit 0
        fi
    fi
    echo "Velociraptor server is not running"
    exit 0
}

do_stop() {
    if [[ -f "$VELO_PID_FILE" ]]; then
        pid=$(cat "$VELO_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "Stopping Velociraptor server (PID ${pid})..."
            kill "$pid" && rm -f "$VELO_PID_FILE"
            log "Stopped."
        else
            warn "PID ${pid} not running, cleaning up."
            rm -f "$VELO_PID_FILE"
        fi
    else
        warn "No PID file found."
    fi
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        --stop)   do_stop ;;
        --status) do_status ;;
        --help|-h)
            echo "Usage: $0 [--stop] [--status]"
            exit 0
            ;;
    esac
done

# Preflight
mkdir -p "$VELO_DIR"

# Download binary if not present
if [[ ! -x "$VELO_BIN" ]]; then
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  DL_ARCH="linux-amd64" ;;
        aarch64) DL_ARCH="linux-arm64" ;;
        *)       err "Unsupported arch: $ARCH"; exit 1 ;;
    esac
    DL_URL="https://github.com/Velocidex/velociraptor/releases/download/v${VELO_VERSION}/velociraptor-v${VELO_VERSION}-${DL_ARCH}"
    log "Downloading Velociraptor ${VELO_VERSION}..."
    curl -fSL -o "$VELO_BIN" "$DL_URL"
    chmod +x "$VELO_BIN"
fi

# Generate config if not present
if [[ ! -f "$VELO_SERVER_CONFIG" ]]; then
    log "Generating server config..."
    "$VELO_BIN" config generate --merge '{
        "GUI": {"bind_address": "0.0.0.0", "bind_port": 8889},
        "Frontend": {"bind_address": "0.0.0.0", "bind_port": 8000},
        "API": {"bind_address": "0.0.0.0", "bind_port": 8001},
        "datastore": {"location": "'"${VELO_DIR}/datastore"'", "filestore_directory": "'"${VELO_DIR}/filestore"'"}
    }' > "$VELO_SERVER_CONFIG"

    "$VELO_BIN" config client --config "$VELO_SERVER_CONFIG" > "$VELO_CLIENT_CONFIG"
    log "Config files generated."

    # Create initial admin user
    log "Creating admin user..."
    "$VELO_BIN" user add --role administrator admin admin \
        --config "$VELO_SERVER_CONFIG" 2>/dev/null || true
fi

# Check if already running
if [[ -f "$VELO_PID_FILE" ]]; then
    pid=$(cat "$VELO_PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
        warn "Already running (PID ${pid}). Use --stop to restart."
        exit 0
    fi
fi

# Start server
log "Starting Velociraptor server..."
nohup "$VELO_BIN" frontend --config "$VELO_SERVER_CONFIG" \
    > "${VELO_DIR}/server.log" 2>&1 &
echo $! > "$VELO_PID_FILE"
log "Server started (PID $(cat "$VELO_PID_FILE"))"

# Wait for API
log "Waiting for API..."
for i in $(seq 1 30); do
    if curl -sk "https://localhost:8889" 2>/dev/null | grep -qi "velociraptor"; then
        log "Velociraptor GUI is ready!"
        break
    fi
    sleep 2
done

HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

echo ""
echo "==========================================================="
echo "  Velociraptor ${VELO_VERSION}"
echo "==========================================================="
echo ""
echo "  GUI     : https://${HOST_IP}:8889"
echo "  API     : https://${HOST_IP}:8001"
echo "  Login   : admin / admin"
echo ""
echo "  Client config: ${VELO_CLIENT_CONFIG}"
echo "  (copy to VM and run: velociraptor.exe client install --config client.config.yaml)"
echo ""
echo "==========================================================="
