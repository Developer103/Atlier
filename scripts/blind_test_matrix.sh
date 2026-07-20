#!/bin/bash
# Blind Mode Stress Test: run Hermes in blind mode across all type×format combos
# Usage: bash scripts/blind_test_matrix.sh [--dry-run]
#
# Each run gets a 60-minute timeout. Results go to results/blind_tests/.
# Requires: LM Studio on :1234, VM SSH on :10022, CrowdStrike snapshot.

set -euo pipefail
cd "$(dirname "$0")/.."

DRY_RUN=false
SKIP_TO=0
FILTER_TYPE=""
FILTER_FORMAT=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --resume)
            SKIP_TO="${2:-0}"
            shift 2
            ;;
        --type)
            FILTER_TYPE="$2"
            shift 2
            ;;
        --format)
            FILTER_FORMAT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--dry-run] [--resume N] [--type TYPE] [--format FORMAT]"
            exit 1
            ;;
    esac
done

if $DRY_RUN; then
    MAX_ROUNDS=1
    TIMEOUT=60
else
    MAX_ROUNDS=999999
    TIMEOUT=3600
fi

LLM_URL="http://localhost:1234"
EDR="crowdstrike"
OUT_DIR="results/blind_tests_v3"
SUMMARY="$OUT_DIR/summary.txt"

# Apply type/format filters
if [[ -n "$FILTER_TYPE" ]]; then
    TYPES=("$FILTER_TYPE")
    SHORT_TYPE=("${FILTER_TYPE:0:4}")
else
    TYPES=(infostealer backdoor)
    SHORT_TYPE=(info back)
fi

if [[ -n "$FILTER_FORMAT" ]]; then
    FORMATS=("$FILTER_FORMAT")
    SHORT_FMT=("${FILTER_FORMAT:0:3}")
else
    FORMATS=(auto pe jscript vbscript batch)
    SHORT_FMT=(auto pe js vbs bat)
fi

cleanup_vm() {
    sshpass -p 'vmuser123' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -p 10022 vmuser@localhost \
        'taskkill /f /im payload.exe /im keylogger.exe 2>nul & del /q C:\Users\vmuser\Desktop\*.exe C:\Users\vmuser\Desktop\*.dll C:\Users\vmuser\Desktop\*.js C:\Users\vmuser\Desktop\*.vbs C:\Users\vmuser\Desktop\*.bat 2>nul & schtasks /delete /tn keylog_test /f 2>nul' \
        >/dev/null 2>&1 || true
    fuser -k 9001/tcp 2>/dev/null || true
}

# ── Prerequisites ──
echo "╔══════════════════════════════════════════════════╗"
echo "║     BLIND MODE STRESS TEST — PREFLIGHT CHECK    ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

echo -n "LLM ($LLM_URL): "
if curl -s --max-time 3 "$LLM_URL/v1/models" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data'][0]['id'])" 2>/dev/null; then
    :
else
    echo "UNREACHABLE — start LM Studio on :1234 first"
    exit 1
fi

echo -n "VM SSH (:10022): "
if sshpass -p 'vmuser123' ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no -p 10022 vmuser@localhost "echo OK" 2>/dev/null; then
    :
else
    echo "UNREACHABLE — start the VM first"
    exit 1
fi

echo ""
mkdir -p "$OUT_DIR"

# ── Header ──
echo "Timeout per run: ${TIMEOUT}s"
echo "Max rounds: $MAX_ROUNDS"
echo "Output: $OUT_DIR/"
echo "Matrix: ${#TYPES[@]} types × ${#FORMATS[@]} formats = $(( ${#TYPES[@]} * ${#FORMATS[@]} )) runs"
if $DRY_RUN; then
    echo "*** DRY RUN MODE (1 round, 60s timeout) ***"
fi
echo ""

# ── Summary header ──
if [[ "$SKIP_TO" -gt 0 && -f "$SUMMARY" ]]; then
    echo "" >> "$SUMMARY"
    echo "# --- Resumed from test $SKIP_TO ($(date '+%Y-%m-%d %H:%M:%S')) ---" >> "$SUMMARY"
else
    printf "%-25s %-10s %-6s %-8s %s\n" "RUN_ID" "STATUS" "ROUNDS" "EXIT" "NOTES" > "$SUMMARY"
    printf "%-25s %-10s %-6s %-8s %s\n" "-------------------------" "----------" "------" "--------" "-----" >> "$SUMMARY"
fi

TOTAL=$(( ${#TYPES[@]} * ${#FORMATS[@]} ))
CURRENT=0
PASS=0
FAIL=0
ERROR=0
TIMEDOUT=0

for ti in "${!TYPES[@]}"; do
    for fi in "${!FORMATS[@]}"; do
        CURRENT=$((CURRENT + 1))
        TYPE="${TYPES[$ti]}"
        FMT="${FORMATS[$fi]}"
        RUN_ID="blind_${SHORT_TYPE[$ti]}_${SHORT_FMT[$fi]}"
        LOG_FILE="$OUT_DIR/${RUN_ID}.log"
        JSON_FILE="$OUT_DIR/${RUN_ID}.json"

        # Skip already-completed runs when resuming
        if [[ $CURRENT -lt $SKIP_TO ]]; then
            echo "[$CURRENT/$TOTAL] $RUN_ID — SKIPPED (resume from $SKIP_TO)"
            continue
        fi

        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[$CURRENT/$TOTAL] $RUN_ID  (type=$TYPE, format=$FMT)"
        echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        cleanup_vm
        # Kill any leftover C2 listeners and wait for port to release
        fuser -k 9001/tcp 2>/dev/null || true
        sleep 2

        # Crash detection: probe the model with a request that would fail
        # if n_ctx is too small (system prompt alone needs ~8K tokens).
        # A 400 error with "n_keep" in the message means the model reloaded
        # with default 4096 context.
        PROBE=$(curl -s -w "%{http_code}" http://localhost:1234/v1/chat/completions \
            -H "Content-Type: application/json" \
            -d '{"model":"qwen3.6-35b-a3b-uncensored-hauhaucs-aggressiv","messages":[{"role":"user","content":"ok"}],"max_tokens":1}' 2>/dev/null)
        PROBE_HTTP="${PROBE: -3}"
        if [[ "$PROBE_HTTP" != "200" ]] || echo "$PROBE" | grep -q "n_keep"; then
            echo "  !! MODEL CRASH DETECTED (HTTP $PROBE_HTTP) — waiting for user to restart LMS..."
            echo "  !! Sleeping 30s then retrying probe..."
            sleep 30
            # Retry once more
            PROBE2=$(curl -s -w "%{http_code}" http://localhost:1234/v1/chat/completions \
                -H "Content-Type: application/json" \
                -d '{"model":"qwen3.6-35b-a3b-uncensored-hauhaucs-aggressiv","messages":[{"role":"user","content":"ok"}],"max_tokens":1}' 2>/dev/null)
            PROBE2_HTTP="${PROBE2: -3}"
            if [[ "$PROBE2_HTTP" != "200" ]]; then
                echo "  !! MODEL STILL DOWN (HTTP $PROBE2_HTTP) — skipping this run"
                STATUS="LMS_CRASH"
                NOTES="LMS not responding"
                printf "%-25s %-10s %-6s %-8s %s\n" "$RUN_ID" "$STATUS" "0" "1" "$NOTES" >> "$SUMMARY"
                ERROR=$((ERROR + 1))
                echo "  Result: $STATUS"
                echo "  Finished: $(date '+%Y-%m-%d %H:%M:%S')"
                echo ""
                continue
            fi
            echo "  !! Model recovered"
        fi

        # Run Hermes with timeout, capture everything
        set +e
        timeout "$TIMEOUT" python3 -m hermes \
            --target-edr "$EDR" \
            --malware-type "$TYPE" \
            --format "$FMT" \
            --blind \
            --llm-url "$LLM_URL" \
            --max-rounds "$MAX_ROUNDS" \
            --json-output \
            -v \
            > "$LOG_FILE" 2>&1
        EXIT_CODE=$?

        # Extract JSON result (multi-line pretty-printed JSON at end of log)
        python3 -c "
import json, re
log = open('$LOG_FILE').read()
# Find the last multi-line JSON block: starts with ^{ on its own line, ends with ^}
# The JSON output from --json-output is the last { ... } block in the file
last_brace = log.rfind('\n{')
if last_brace >= 0:
    candidate = log[last_brace+1:]
    # Find the closing brace
    close = candidate.find('\n}')
    if close >= 0:
        json_str = candidate[:close+2]
        try:
            result = json.loads(json_str)
            with open('$JSON_FILE', 'w') as f:
                json.dump(result, f, indent=2)
            status = result.get('status', 'unknown')
            rounds = result.get('round', '?')
            print(f'{status}|{rounds}')
        except json.JSONDecodeError:
            print('parse_error|0')
    else:
        print('no_json|0')
else:
    print('no_json|0')
" > /tmp/blind_result_parse.txt 2>&1 || echo "parse_error|0" > /tmp/blind_result_parse.txt

        PARSED=$(cat /tmp/blind_result_parse.txt)
        STATUS=$(echo "$PARSED" | cut -d'|' -f1)
        ROUNDS=$(echo "$PARSED" | cut -d'|' -f2)

        NOTES=""
        if [[ $EXIT_CODE -eq 124 ]]; then
            STATUS="TIMEOUT"
            NOTES="killed after ${TIMEOUT}s (60min)"
            TIMEDOUT=$((TIMEDOUT + 1))
        elif [[ $EXIT_CODE -ne 0 && "$STATUS" != "error" ]]; then
            STATUS="CRASH"
            NOTES="exit code $EXIT_CODE"
            ERROR=$((ERROR + 1))
        elif [[ "$STATUS" == "success" ]]; then
            PASS=$((PASS + 1))
        elif [[ "$STATUS" == "error" || "$STATUS" == "parse_error" || "$STATUS" == "no_json" ]]; then
            # Extract error from log
            NOTES=$(grep -i 'error\|traceback\|exception' "$LOG_FILE" | tail -1 | head -c 60)
            ERROR=$((ERROR + 1))
        else
            FAIL=$((FAIL + 1))
        fi

        printf "%-25s %-10s %-6s %-8s %s\n" "$RUN_ID" "$STATUS" "$ROUNDS" "$EXIT_CODE" "$NOTES" >> "$SUMMARY"
        echo "  Result: $STATUS (rounds=$ROUNDS, exit=$EXIT_CODE)"
        echo "  Finished: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
    done
done

# ── Final cleanup ──
cleanup_vm

# ── Final summary ──
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║              BLIND MODE TEST RESULTS             ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
cat "$SUMMARY"
echo ""
echo "Total: $TOTAL runs"
echo "  SUCCESS:  $PASS"
echo "  FAIL:     $FAIL"
echo "  ERROR:    $ERROR"
echo "  TIMEOUT:  $TIMEDOUT"
echo ""
echo "Logs: $OUT_DIR/"
