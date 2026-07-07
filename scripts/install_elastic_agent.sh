#!/usr/bin/env bash
# install_elastic_agent.sh — Install Elastic Agent on the Windows VM
# Usage:
#   ./install_elastic_agent.sh <enrollment_token>
#   ./install_elastic_agent.sh <enrollment_token> --no-defender
#   ./install_elastic_agent.sh --auto   (reads token from /tmp/elastic-docker/enrollment_token)
set -euo pipefail

ELASTIC_VERSION="8.15.3"
VM_PORT=10022
VM_USER="vmuser"
VM_PASS="vmuser123"
FLEET_URL="https://10.0.2.2:8220"
TOKEN_FILE="/tmp/elastic-docker/enrollment_token"
AGENT_ZIP="elastic-agent-${ELASTIC_VERSION}-windows-x86_64.zip"
AGENT_URL="https://artifacts.elastic.co/downloads/beats/elastic-agent/${AGENT_ZIP}"
AGENT_LOCAL="/tmp/${AGENT_ZIP}"

DISABLE_DEFENDER=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

SSH="sshpass -p '${VM_PASS}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p ${VM_PORT} ${VM_USER}@localhost"
SCP="sshpass -p '${VM_PASS}' scp -o StrictHostKeyChecking=no -P ${VM_PORT}"

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
ENROLLMENT_TOKEN=""

for arg in "$@"; do
    case "$arg" in
        --no-defender) DISABLE_DEFENDER=true ;;
        --auto)
            if [[ -f "$TOKEN_FILE" ]]; then
                ENROLLMENT_TOKEN=$(cat "$TOKEN_FILE")
            else
                err "Token file not found: ${TOKEN_FILE}"
                err "Run scripts/setup_elastic.sh first."
                exit 1
            fi
            ;;
        --help|-h)
            echo "Usage: $0 <enrollment_token> [--no-defender]"
            echo "       $0 --auto [--no-defender]"
            echo ""
            echo "  --auto          Read token from ${TOKEN_FILE}"
            echo "  --no-defender   Disable Windows Defender real-time protection"
            exit 0
            ;;
        *)
            if [[ -z "$ENROLLMENT_TOKEN" ]]; then
                ENROLLMENT_TOKEN="$arg"
            fi
            ;;
    esac
done

if [[ -z "$ENROLLMENT_TOKEN" ]]; then
    err "Usage: $0 <enrollment_token> [--no-defender]"
    err "   or: $0 --auto [--no-defender]"
    exit 1
fi

# ---------------------------------------------------------------------------
# Preflight: check VM is alive
# ---------------------------------------------------------------------------
log "Checking VM connectivity..."
if ! eval $SSH "echo VM_ALIVE" 2>/dev/null | tr -d '\r' | grep -q "VM_ALIVE"; then
    err "Cannot reach VM at localhost:${VM_PORT}"
    exit 1
fi
log "VM is alive."

# ---------------------------------------------------------------------------
# Check if agent already installed
# ---------------------------------------------------------------------------
AGENT_STATUS=$(eval $SSH "'sc query \"Elastic Agent\" 2>nul | findstr STATE'" 2>/dev/null | tr -d '\r' || true)
if echo "$AGENT_STATUS" | grep -qi "RUNNING"; then
    warn "Elastic Agent is already installed and running."
    warn "To reinstall, first run on VM: elastic-agent uninstall"
    exit 0
fi

# ---------------------------------------------------------------------------
# Optionally disable Defender
# ---------------------------------------------------------------------------
if [[ "$DISABLE_DEFENDER" == "true" ]]; then
    log "Disabling Windows Defender real-time protection..."
    eval $SSH "'powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring \$true\"'" 2>/dev/null || true

    DEFENDER_STATUS=$(eval $SSH "'powershell -Command \"(Get-MpComputerStatus).RealTimeProtectionEnabled\"'" 2>/dev/null | tr -d '\r' || true)
    if [[ "$DEFENDER_STATUS" == "False" ]]; then
        log "Defender real-time protection disabled."
    else
        warn "Defender may still be active (Tamper Protection can block this)."
        warn "Disable manually via Windows Security UI if needed."
    fi
fi

# ---------------------------------------------------------------------------
# Download agent zip (cache on host)
# ---------------------------------------------------------------------------
if [[ -f "$AGENT_LOCAL" ]]; then
    log "Agent zip already cached: ${AGENT_LOCAL}"
else
    log "Downloading Elastic Agent ${ELASTIC_VERSION}..."
    curl -L --progress-bar -o "$AGENT_LOCAL" "$AGENT_URL"
    if [[ ! -f "$AGENT_LOCAL" ]]; then
        err "Download failed."
        exit 1
    fi
    log "Downloaded: $(du -h "$AGENT_LOCAL" | cut -f1)"
fi

# ---------------------------------------------------------------------------
# Upload to VM
# ---------------------------------------------------------------------------
log "Uploading agent zip to VM..."
eval $SCP "'${AGENT_LOCAL}'" "${VM_USER}@localhost:'C:\\Users\\${VM_USER}\\Desktop\\${AGENT_ZIP}'" 2>/dev/null
log "Upload complete."

# ---------------------------------------------------------------------------
# Extract and install on VM
# ---------------------------------------------------------------------------
log "Extracting agent on VM..."
eval $SSH "'powershell -Command \"Expand-Archive -Force -Path C:\\Users\\${VM_USER}\\Desktop\\${AGENT_ZIP} -DestinationPath C:\\Users\\${VM_USER}\\Desktop\\elastic-agent\"'" 2>/dev/null

AGENT_DIR="C:\\Users\\${VM_USER}\\Desktop\\elastic-agent\\elastic-agent-${ELASTIC_VERSION}-windows-x86_64"

log "Installing Elastic Agent..."
eval $SSH "'cmd /c \"cd /d ${AGENT_DIR} && elastic-agent.exe install --url=${FLEET_URL} --enrollment-token=${ENROLLMENT_TOKEN} --insecure --force --non-interactive\"'" 2>/dev/null

# ---------------------------------------------------------------------------
# Verify installation
# ---------------------------------------------------------------------------
log "Verifying agent service..."
sleep 10

AGENT_RUNNING=$(eval $SSH "'sc query \"Elastic Agent\" 2>nul | findstr STATE'" 2>/dev/null | tr -d '\r' || true)
if echo "$AGENT_RUNNING" | grep -qi "RUNNING"; then
    log "Elastic Agent service is RUNNING."
else
    warn "Agent service state: ${AGENT_RUNNING:-unknown}"
    warn "Check: sc query \"Elastic Agent\" on the VM"
fi

# Check for endpoint driver
DRIVER_STATUS=$(eval $SSH "'sc query ElasticEndpointDriver 2>nul | findstr STATE'" 2>/dev/null | tr -d '\r' || true)
if echo "$DRIVER_STATUS" | grep -qi "RUNNING"; then
    log "ElasticEndpoint kernel driver is RUNNING."
else
    warn "Kernel driver state: ${DRIVER_STATUS:-not found}"
    warn "Elastic Defend integration may need activation in Kibana."
fi

# ---------------------------------------------------------------------------
# Cleanup zip on VM
# ---------------------------------------------------------------------------
eval $SSH "'del /q C:\\Users\\${VM_USER}\\Desktop\\${AGENT_ZIP} 2>nul'" 2>/dev/null || true
eval $SSH "'rmdir /s /q C:\\Users\\${VM_USER}\\Desktop\\elastic-agent 2>nul'" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "==========================================================="
echo "  Elastic Agent Installation Complete"
echo "==========================================================="
echo ""
echo "  Fleet URL        : ${FLEET_URL}"
echo "  Agent service    : ${AGENT_RUNNING:-unknown}"
echo "  Kernel driver    : ${DRIVER_STATUS:-unknown}"
echo "  Defender         : $(if [[ "$DISABLE_DEFENDER" == "true" ]]; then echo "DISABLED"; else echo "ENABLED"; fi)"
echo ""
echo "  Verify in Kibana : Fleet > Agents (should show 'Healthy')"
echo "  Query alerts     :"
echo "    curl -sk -u elastic:changeme \\"
echo "      'https://localhost:9200/.alerts-security*/_search?q=host.name:MalwareVM&size=10'"
echo ""
echo "==========================================================="
echo ""
