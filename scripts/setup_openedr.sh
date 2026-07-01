#!/usr/bin/env bash
# setup_openedr.sh — Install OpenEDR agent on a Windows VM via SSH
# Usage: ./setup_openedr.sh <vm_ssh_port> [vm_user] [vm_pass]
# OpenEDR is agent-only (no server component) — reads events from local log file.
set -euo pipefail

VM_PORT="${1:-2222}"
VM_USER="${2:-vmuser}"
VM_PASS="${3:-vmuser}"
OPENEDR_MSI_URL="https://github.com/ComodoSecurity/openedr/releases/latest/download/openedr-agent.msi"
OPENEDR_DIR="/tmp/openedr"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

ssh_cmd() {
    sshpass -p "$VM_PASS" ssh $SSH_OPTS -p "$VM_PORT" "${VM_USER}@localhost" "$1"
}

scp_to() {
    sshpass -p "$VM_PASS" scp $SSH_OPTS -P "$VM_PORT" "$1" "${VM_USER}@localhost:$2"
}

# Check if already installed
log "Checking if OpenEDR is already installed on VM..."
installed=$(ssh_cmd 'powershell -NoProfile -Command "Test-Path \"C:\\Program Files\\OpenEDR\\openedr.exe\""' 2>/dev/null || echo "False")
if [[ "$installed" == *"True"* ]]; then
    warn "OpenEDR is already installed on the VM."
    exit 0
fi

# Download MSI if not cached
mkdir -p "$OPENEDR_DIR"
MSI_LOCAL="${OPENEDR_DIR}/openedr-agent.msi"
if [[ ! -f "$MSI_LOCAL" ]]; then
    log "Downloading OpenEDR agent MSI..."
    curl -fSL -o "$MSI_LOCAL" "$OPENEDR_MSI_URL" || {
        warn "Download failed — OpenEDR may need manual download from GitHub."
        warn "Place the MSI at: ${MSI_LOCAL}"
        exit 1
    }
fi

# Upload MSI to VM
log "Uploading MSI to VM..."
scp_to "$MSI_LOCAL" 'C:\Users\vmuser\openedr-agent.msi'

# Install silently
log "Installing OpenEDR agent on VM..."
ssh_cmd 'msiexec /i C:\Users\vmuser\openedr-agent.msi /q' || {
    warn "MSI install returned non-zero (may still succeed)."
}

# Verify installation
sleep 5
log "Verifying installation..."
verified=$(ssh_cmd 'powershell -NoProfile -Command "Test-Path \"C:\\ProgramData\\OpenEDR\\events.json\""' 2>/dev/null || echo "False")
if [[ "$verified" == *"True"* ]]; then
    log "OpenEDR installed and events.json exists."
else
    warn "events.json not yet created — agent may need time to start."
fi

echo ""
echo "==========================================================="
echo "  OpenEDR Agent Installed"
echo "==========================================================="
echo ""
echo "  Events log: C:\\ProgramData\\OpenEDR\\events.json"
echo "  Detection:  read events.json via SSH (log_file method)"
echo ""
echo "  spec.yaml config:"
echo "    edrs:"
echo "      - openedr"
echo ""
echo "==========================================================="
