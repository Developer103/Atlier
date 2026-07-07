#!/bin/bash
# test_elastic.sh — Test a payload against Elastic Defend EDR
# Usage: ./scripts/test_elastic.sh <payload.exe> [c2_port]
#
# Deploys binary to VM, executes, waits for Elastic to process,
# queries for new security alerts, cleans up VM.
# Returns 0 if NO alerts (evasion success), 1 if alerts fired.

set -e

EXE="${1:?Usage: $0 <payload.exe> [c2_port]}"
C2_PORT="${2:-9001}"
C2_IP="10.0.2.2"
VM_PORT="${VM_PORT:-10022}"
VM_USER="${VM_USER:-vmuser}"
VM_PASS="${VM_PASS:-vmuser123}"

ES_URL="https://localhost:9200"
ES_AUTH="elastic:changeme"
ALERT_INDEX=".alerts-security*"
ENDPOINT_INDEX="logs-endpoint.alerts-default"

SSH="sshpass -p $VM_PASS ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $VM_PORT $VM_USER@localhost"
SCP="sshpass -p $VM_PASS scp -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P $VM_PORT"

PAYLOAD_NAME="svchost_test.exe"
REMOTE_PATH="C:\\Users\\${VM_USER}\\${PAYLOAD_NAME}"
WAIT_SECS=45

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup() {
    kill $C2_PID 2>/dev/null || true
    $SSH "taskkill /F /IM $PAYLOAD_NAME 2>nul & del /Q \"$REMOTE_PATH\" 2>nul & schtasks /Delete /TN maltest /F 2>nul" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Elastic EDR Test ==="
echo "Payload: $(basename $EXE)"
echo ""

# Record pre-test alert count
PRE_ALERTS=$(curl -sk -u "$ES_AUTH" "${ES_URL}/${ALERT_INDEX}/_count" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
PRE_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[1/5] Pre-test alerts: ${PRE_ALERTS}"

# Upload payload
echo "[2/5] Uploading payload..."
$SCP "$EXE" "${VM_USER}@localhost:${PAYLOAD_NAME}" 2>/dev/null

# Start C2 listener (background, timeout)
C2_OUT="/tmp/c2_elastic_$$.bin"
timeout ${WAIT_SECS} nc -l -p "$C2_PORT" > "$C2_OUT" 2>/dev/null &
C2_PID=$!

# Execute via schtasks
echo "[3/5] Executing payload on VM..."
$SSH "schtasks /Create /TN maltest /SC ONCE /ST 00:00 /TR \"$REMOTE_PATH\" /F /RL HIGHEST 2>nul && schtasks /Run /TN maltest 2>nul" 2>/dev/null || true

# Wait for execution + Elastic processing
echo "[4/5] Waiting ${WAIT_SECS}s for execution + Elastic event processing..."
for i in $(seq 1 $WAIT_SECS); do
    printf "\r  %d/%ds" "$i" "$WAIT_SECS"
    sleep 1
done
echo ""

# Check for new alerts
echo "[5/5] Checking for Elastic alerts..."

POST_ALERTS=$(curl -sk -u "$ES_AUTH" "${ES_URL}/${ALERT_INDEX}/_count" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
NEW_ALERTS=$((POST_ALERTS - PRE_ALERTS))

# Query new alerts since our test started
ALERT_DETAILS=$(curl -sk -u "$ES_AUTH" \
    "${ES_URL}/${ALERT_INDEX}/_search" \
    -H "Content-Type: application/json" \
    -d "{
        \"size\": 50,
        \"query\": {
            \"range\": {
                \"@timestamp\": {
                    \"gte\": \"${PRE_TS}\"
                }
            }
        },
        \"sort\": [{\"@timestamp\": \"asc\"}]
    }" 2>/dev/null)

# Also check endpoint-specific alerts
EP_ALERTS=$(curl -sk -u "$ES_AUTH" \
    "${ES_URL}/logs-endpoint.alerts-default/_search" \
    -H "Content-Type: application/json" \
    -d "{
        \"size\": 50,
        \"query\": {
            \"range\": {
                \"@timestamp\": {
                    \"gte\": \"${PRE_TS}\"
                }
            }
        },
        \"sort\": [{\"@timestamp\": \"asc\"}]
    }" 2>/dev/null)

# Parse and display
echo ""
echo "--- DETECTION RESULTS ---"

RULE_NAMES=$(echo "$ALERT_DETAILS" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    hits = d.get('hits',{}).get('hits',[])
    seen = set()
    for h in hits:
        s = h['_source']
        rule = s.get('kibana.alert.rule.name','?')
        sev = s.get('kibana.alert.severity','?')
        proc = s.get('process',{}).get('name','?')
        cmd = s.get('process',{}).get('command_line','')[:100]
        key = f'{rule}|{proc}'
        if key not in seen:
            seen.add(key)
            print(f'  RULE: {rule}')
            print(f'    Severity: {sev}')
            print(f'    Process: {proc}')
            print(f'    Command: {cmd}')
            print()
except: pass
" 2>/dev/null)

EP_RULE_NAMES=$(echo "$EP_ALERTS" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    hits = d.get('hits',{}).get('hits',[])
    seen = set()
    for h in hits:
        s = h['_source']
        rule = s.get('rule',{}).get('description','') or s.get('Endpoint.policy.applied.name','?')
        action = s.get('Endpoint.policy.applied.response',{}).get('actions',{})
        proc = s.get('process',{}).get('name','?')
        key = f'{rule}|{proc}'
        if key not in seen:
            seen.add(key)
            print(f'  ENDPOINT: {rule}')
            print(f'    Process: {proc}')
            print()
except: pass
" 2>/dev/null)

C2_SIZE=0
if [ -f "$C2_OUT" ]; then
    C2_SIZE=$(stat -c%s "$C2_OUT" 2>/dev/null || echo 0)
fi

echo "Security rule alerts: ${NEW_ALERTS}"
if [ -n "$RULE_NAMES" ]; then
    echo "$RULE_NAMES"
fi
if [ -n "$EP_RULE_NAMES" ]; then
    echo "$EP_RULE_NAMES"
fi
echo "C2 data received: ${C2_SIZE} bytes"
echo ""

# Verdict
if [ "$NEW_ALERTS" -eq 0 ] && [ -z "$EP_RULE_NAMES" ]; then
    echo -e "${GREEN}VERDICT: EVASION SUCCESS — zero detection${NC}"
    exit 0
else
    echo -e "${RED}VERDICT: DETECTED — ${NEW_ALERTS} alert(s) fired${NC}"
    exit 1
fi
