#!/bin/bash
# test_elastic_detailed.sh — Detailed Elastic EDR test with full alert analysis
# Usage: ./scripts/test_elastic_detailed.sh <payload.exe> [label] [c2_port]
# Returns detailed alert analysis including process chains

EXE="${1:?Usage: $0 <payload.exe> [label] [c2_port]}"
LABEL="${2:-$(basename $(dirname $EXE))}"
C2_PORT="${3:-9001}"

VM_PORT=10022
VM_USER=vmuser
VM_PASS=vmuser123
ES_URL="https://localhost:9200"
ES_AUTH="elastic:changeme"

SSH="sshpass -p $VM_PASS ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $VM_PORT $VM_USER@localhost"
SCP="sshpass -p $VM_PASS scp -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P $VM_PORT"

PAYLOAD_NAME="svchost_test.exe"

echo "=== DETAILED ELASTIC EDR TEST: ${LABEL} ==="
echo ""

# Clean VM
$SSH "taskkill /F /IM $PAYLOAD_NAME 2>nul; del /Q C:\\Users\\${VM_USER}\\${PAYLOAD_NAME} 2>nul; schtasks /Delete /TN maltest /F 2>nul" 2>/dev/null || true

PRE_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "Timestamp baseline: ${PRE_TS}"

# Upload
echo "[1] Uploading..."
$SCP "$EXE" "${VM_USER}@localhost:${PAYLOAD_NAME}" 2>/dev/null

# C2 listener
C2_OUT="/tmp/c2_detail_$$.bin"
timeout 50 nc -l -p "$C2_PORT" > "$C2_OUT" 2>/dev/null &
C2_PID=$!

# Execute
echo "[2] Executing..."
$SSH "schtasks /Create /TN maltest /SC ONCE /ST 00:00 /TR C:\\Users\\${VM_USER}\\${PAYLOAD_NAME} /F /RL HIGHEST 2>nul && schtasks /Run /TN maltest 2>nul" 2>/dev/null

# Wait
echo "[3] Waiting 50s..."
for i in $(seq 1 50); do printf "\r    %d/50s" "$i"; sleep 1; done
echo ""

kill $C2_PID 2>/dev/null || true
wait $C2_PID 2>/dev/null || true

C2_SIZE=0
[ -f "$C2_OUT" ] && C2_SIZE=$(stat -c%s "$C2_OUT" 2>/dev/null || echo 0)

echo "[4] Analyzing alerts..."
echo ""

# Get ALL alerts (no filtering)
python3 -c "
import json, urllib.request, ssl, base64

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

auth = base64.b64encode(b'elastic:changeme').decode()
url = 'https://localhost:9200/.alerts-security*/_search'
body = json.dumps({
    'size': 100,
    'query': {'range': {'@timestamp': {'gte': '${PRE_TS}'}}},
    'sort': [{'@timestamp': 'asc'}],
    '_source': [
        'kibana.alert.rule.name', 'kibana.alert.severity',
        'process.name', 'process.args', 'process.executable',
        'process.parent.name', 'process.parent.executable',
        'process.parent.args',
        'file.name', 'file.path'
    ]
}).encode()

req = urllib.request.Request(url, data=body, headers={
    'Authorization': f'Basic {auth}',
    'Content-Type': 'application/json'
})
resp = urllib.request.urlopen(req, context=ctx)
data = json.loads(resp.read())

hits = data.get('hits',{}).get('hits',[])
total = len(hits)

# Categorize
fp_keywords = ['ElasticEndpoint', 'ElasticEndpointDriver', 'Elastic Agent', 'elastic-agent']
real_alerts = []
fp_alerts = []

for h in hits:
    s = h['_source']
    rule = s.get('kibana.alert.rule.name','?')
    sev = s.get('kibana.alert.severity','?')
    proc = s.get('process',{})
    pname = proc.get('name','?')
    pargs = ' '.join(proc.get('args',[])) if proc.get('args') else '?'
    pexe = proc.get('executable','?')
    parent = s.get('process',{}).get('parent',{})
    parent_name = parent.get('name','?') if parent else '?'
    parent_exe = parent.get('executable','?') if parent else '?'
    fname = s.get('file',{}).get('name','') if s.get('file') else ''

    is_fp = False
    for kw in fp_keywords:
        if kw.lower() in pargs.lower() or kw.lower() in str(fname).lower():
            is_fp = True
            break

    # schtasks alerts from our deploy method
    if rule == 'Local Scheduled Task Creation' and 'maltest' in pargs.lower():
        is_fp = True

    entry = {
        'rule': rule, 'severity': sev,
        'process': pname, 'args': pargs[:100],
        'executable': pexe,
        'parent': parent_name, 'parent_exe': parent_exe,
        'file': fname, 'is_fp': is_fp
    }
    if is_fp:
        fp_alerts.append(entry)
    else:
        real_alerts.append(entry)

print(f'Total alerts: {total}')
print(f'  False positives (test infra): {len(fp_alerts)}')
print(f'  Real detections: {len(real_alerts)}')
print()

if fp_alerts:
    print('--- FALSE POSITIVES (filtered) ---')
    seen = set()
    for a in fp_alerts:
        key = f\"{a['rule']}|{a['process']}\"
        if key not in seen:
            seen.add(key)
            print(f\"  [{a['severity']}] {a['rule']}\")
            print(f\"    Process: {a['process']} ({a['args'][:60]})\")
            print(f\"    Parent: {a['parent']}\")
    print()

if real_alerts:
    print('--- REAL DETECTIONS ---')
    seen = set()
    for a in real_alerts:
        key = f\"{a['rule']}|{a['process']}\"
        if key not in seen:
            seen.add(key)
            print(f\"  [{a['severity']}] {a['rule']}\")
            print(f\"    Process: {a['process']} ({a['args'][:80]})\")
            print(f\"    Executable: {a['executable']}\")
            print(f\"    Parent: {a['parent']} ({a['parent_exe']})\")
            if a['file']:
                print(f\"    File: {a['file']}\")
    print()
else:
    print('--- NO REAL DETECTIONS ---')
    print()

print(f'C2 data received: ${C2_SIZE} bytes')
print()

if real_alerts:
    print('VERDICT: DETECTED')
else:
    print('VERDICT: EVASION SUCCESS')
" 2>/dev/null

# Cleanup
$SSH "taskkill /F /IM $PAYLOAD_NAME 2>nul; del /Q C:\\Users\\${VM_USER}\\${PAYLOAD_NAME} 2>nul; schtasks /Delete /TN maltest /F 2>nul" 2>/dev/null || true
rm -f "$C2_OUT"
echo ""
