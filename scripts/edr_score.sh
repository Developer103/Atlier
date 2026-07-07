#!/bin/bash
# EDR Behavioral Detection Score — Sysmon + Sigma Rules
# Models CrowdStrike Falcon-like behavioral detection
#
# Usage:
#   ./scripts/edr_score.sh <payload.exe>                    # Upload, run, score
#   ./scripts/edr_score.sh <payload.exe> --type backdoor    # Backdoor (starts C2 listener)
#   ./scripts/edr_score.sh --score-only /path/to/evtx       # Score existing evtx file

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CHAINSAW="$PROJECT_DIR/tools/chainsaw/chainsaw"
SIGMA_RULES="$PROJECT_DIR/tools/sigma/rules/windows"
SIGMA_HUNTING="$PROJECT_DIR/tools/sigma/rules-threat-hunting/windows"
SIGMA_EMERGING="$PROJECT_DIR/tools/sigma/rules-emerging-threats"
SIGMA_CUSTOM="$PROJECT_DIR/tools/sigma/rules/custom"
MAPPINGS="$PROJECT_DIR/tools/chainsaw/mappings/sigma-event-logs-all.yml"
RESULTS_DIR="$PROJECT_DIR/results/edr_scores"

VM_PORT=${VM_PORT:-10022}
VM_USER=${VM_USER:-vmuser}
VM_PASS=${VM_PASS:-vmuser123}
C2_PORT=${C2_PORT:-9001}
PAYLOAD_TYPE="infostealer"

SSH="sshpass -p '$VM_PASS' ssh -o StrictHostKeyChecking=no -p $VM_PORT $VM_USER@localhost"
SCP="sshpass -p '$VM_PASS' scp -o StrictHostKeyChecking=no -P $VM_PORT"

mkdir -p "$RESULTS_DIR"

score_only=""
payload=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --score-only) score_only="$2"; shift 2 ;;
        --type) PAYLOAD_TYPE="$2"; shift 2 ;;
        *) payload="$1"; shift ;;
    esac
done

run_score() {
    local evtx_file="$1"
    local ts=$(date +%Y%m%d_%H%M%S)
    local report="$RESULTS_DIR/score_${ts}.txt"

    echo ""
    echo "======================================"
    echo "  EDR BEHAVIORAL DETECTION SCORE"
    echo "======================================"
    echo ""

    # Run chainsaw with sigma rules — JSON output for reliable parsing
    echo "[*] Scanning with Sigma rules..."
    "$CHAINSAW" hunt "$evtx_file" \
        -s "$SIGMA_RULES" \
        -s "$SIGMA_HUNTING" \
        -s "$SIGMA_EMERGING" \
        -s "$SIGMA_CUSTOM" \
        --mapping "$MAPPINGS" \
        --skip-errors \
        --json \
        2>/dev/null > "${report}.json" || true

    # Also save human-readable version
    "$CHAINSAW" hunt "$evtx_file" \
        -s "$SIGMA_RULES" \
        -s "$SIGMA_HUNTING" \
        -s "$SIGMA_EMERGING" \
        -s "$SIGMA_CUSTOM" \
        --mapping "$MAPPINGS" \
        --skip-errors \
        2>/dev/null > "$report" || true

    # Parse JSON for accurate counts, filtering out test harness noise
    local results
    results=$(python3 -c "
import json, sys

with open('${report}.json') as f:
    data = json.load(f)

# Test harness processes to filter out
harness = {'cmd.exe', 'schtasks.exe', 'wevtutil.exe', 'sshd.exe', 'svchost.exe', 'conhost.exe'}

total = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
payload = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
payload_rules = []
harness_rules = []

for hit in data:
    # Each top-level entry IS a detection (not nested under 'detections')
    sev = hit.get('level', 'low').lower()
    if sev not in total:
        sev = 'low'
    total[sev] += 1

    # Extract image from nested Event structure
    event = hit.get('document', {}).get('data', {})
    ev_data = event.get('Event', {}).get('EventData', {}) if 'Event' in event else event
    image = ev_data.get('Image', '')

    is_harness = any(h in image.lower() for h in harness)

    name = hit.get('name', 'unknown')
    tags = hit.get('tags', [])
    if is_harness:
        harness_rules.append(name)
    else:
        payload[sev] += 1
        payload_rules.append((sev, name, tags))

print(f'TOTAL_DETECTIONS={sum(total.values())}')
print(f'HARNESS_NOISE={sum(total.values()) - sum(payload.values())}')
print(f'PAYLOAD_CRITICAL={payload[\"critical\"]}')
print(f'PAYLOAD_HIGH={payload[\"high\"]}')
print(f'PAYLOAD_MEDIUM={payload[\"medium\"]}')
print(f'PAYLOAD_LOW={payload[\"low\"]}')
print(f'PAYLOAD_INFO={payload[\"informational\"]}')
seen = set()
for sev, name, tags in payload_rules:
    key = f'{sev}:{name}'
    if key not in seen:
        seen.add(key)
        tag_str = ','.join(t for t in tags if t.startswith('attack.'))
        print(f'RULE:{sev}|{name}|{tag_str}')
" 2>/dev/null) || results="PARSE_ERROR=1"

    if echo "$results" | grep -q "PARSE_ERROR"; then
        echo "  (JSON parse failed, falling back to raw output)"
        echo "  See: $report"
        echo "======================================"
        return
    fi

    eval "$(echo "$results" | grep -v '^RULE:')"

    echo ""
    echo "  Raw Detections:    $TOTAL_DETECTIONS"
    echo "  Test Harness:     -$HARNESS_NOISE (SSH, schtasks, wevtutil — not payload)"
    echo ""
    echo "  PAYLOAD Detections:"
    echo "  ─────────────────────"
    echo "  CRITICAL: $PAYLOAD_CRITICAL  (CrowdStrike: BLOCKED + alert)"
    echo "  HIGH:     $PAYLOAD_HIGH  (CrowdStrike: BLOCKED + alert)"
    echo "  MEDIUM:   $PAYLOAD_MEDIUM  (CrowdStrike: ALERT only)"
    echo "  LOW:      $PAYLOAD_LOW  (CrowdStrike: telemetry)"
    echo ""

    # Display payload-specific rules
    local payload_total=$((PAYLOAD_CRITICAL + PAYLOAD_HIGH + PAYLOAD_MEDIUM + PAYLOAD_LOW + PAYLOAD_INFO))
    if [ "$payload_total" -gt 0 ]; then
        echo "  Triggered Rules (PAYLOAD ONLY):"
        echo "  ─────────────────────"
        echo "$results" | grep "^RULE:" | sed 's/^RULE://' | while read -r line; do
            sev="${line%%|*}"
            rest="${line#*|}"
            name="${rest%%|*}"
            tags="${rest#*|}"
            if [ "$tags" != "$name" ] && [ -n "$tags" ]; then
                echo "    [$sev] $name  ($tags)"
            else
                echo "    [$sev] $name"
            fi
        done
    else
        echo "  No payload-specific rules triggered."
    fi

    echo ""

    local blocked=$((PAYLOAD_CRITICAL + PAYLOAD_HIGH))
    if [ "$blocked" -gt 0 ]; then
        echo "  VERDICT: WOULD BE BLOCKED by CrowdStrike ($blocked critical/high hits)"
        echo "           Action: Fix evasion for these specific detections"
    elif [ "$PAYLOAD_MEDIUM" -gt 0 ]; then
        echo "  VERDICT: ALERT ONLY — not blocked, but analyst would investigate ($PAYLOAD_MEDIUM medium hits)"
        echo "           Action: Reduce medium hits to minimize SOC attention"
    else
        echo "  VERDICT: CLEAN — no behavioral detections"
        echo "           CrowdStrike equivalent: payload would NOT be flagged"
    fi

    echo ""
    echo "  Full report: $report"
    echo "======================================"
    echo ""
}

if [ -n "$score_only" ]; then
    run_score "$score_only"
    exit 0
fi

if [ -z "$payload" ]; then
    echo "Usage: $0 <payload.exe> [--type infostealer|backdoor|keylogger]"
    exit 1
fi

ts=$(date +%Y%m%d_%H%M%S)
evtx_file="$RESULTS_DIR/sysmon_${ts}.evtx"

echo "[1/6] Clearing Sysmon logs..."
eval $SSH "'wevtutil cl Microsoft-Windows-Sysmon/Operational'" 2>/dev/null
sleep 2

echo "[2/6] Uploading payload..."
eval $SCP "'$payload'" "'$VM_USER@localhost:C:/Users/$VM_USER/Desktop/payload.exe'" 2>/dev/null
sleep 3

# Check Defender didn't eat it
exist=$(eval $SSH "'if exist C:\\Users\\$VM_USER\\Desktop\\payload.exe (echo EXISTS) else (echo GONE)'" 2>&1 | tr -d '\r')
if [ "$exist" = "GONE" ]; then
    echo "  QUARANTINED by Defender before execution!"
    exit 2
fi

echo "[3/6] Executing payload..."
# Start C2 listener BEFORE payload for infostealers (one-shot connection)
fuser -k $C2_PORT/tcp 2>/dev/null || true
sleep 1

if [ "$PAYLOAD_TYPE" = "backdoor" ]; then
    timeout 60 python3 "$SCRIPT_DIR/c2_backdoor.py" --test-sequence --port $C2_PORT >/dev/null 2>&1 &
    C2_PID=$!
    sleep 2
elif [ "$PAYLOAD_TYPE" = "infostealer" ]; then
    timeout 60 nc -l -p $C2_PORT > /dev/null &
    C2_PID=$!
    sleep 1
fi

eval $SSH "'schtasks /create /tn edrtest /tr \"C:\\Users\\$VM_USER\\Desktop\\payload.exe\" /sc once /st 00:00 /f'" >/dev/null 2>&1 || true
eval $SSH "'schtasks /run /tn edrtest'" >/dev/null 2>&1 || true

echo "[4/6] Waiting for payload to finish..."
if [ "$PAYLOAD_TYPE" = "keylogger" ]; then
    sleep 40
else
    wait $C2_PID 2>/dev/null || true
fi
sleep 5

echo "[5/6] Exporting Sysmon logs..."
eval $SSH "'del C:\\Users\\$VM_USER\\Desktop\\sysmon.evtx 2>nul && wevtutil epl Microsoft-Windows-Sysmon/Operational C:\\Users\\$VM_USER\\Desktop\\sysmon.evtx'" 2>/dev/null
sleep 1
eval $SCP "'$VM_USER@localhost:C:/Users/$VM_USER/Desktop/sysmon.evtx'" "'$evtx_file'" 2>/dev/null

if [ ! -f "$evtx_file" ] || [ ! -s "$evtx_file" ]; then
    echo "ERROR: Failed to export Sysmon logs"
    exit 3
fi

evtx_size=$(stat -c%s "$evtx_file")
echo "  Exported: $evtx_file ($evtx_size bytes)"

echo "[6/6] Scoring..."
run_score "$evtx_file"

# Cleanup VM
eval $SSH "'taskkill /f /im payload.exe 2>nul & del C:\\Users\\$VM_USER\\Desktop\\payload.exe 2>nul & del C:\\Users\\$VM_USER\\Desktop\\sysmon.evtx 2>nul & schtasks /delete /tn edrtest /f 2>nul'" 2>/dev/null
