#!/bin/bash
# Run evasion exams — normal, hard, or insane difficulty
# Usage:
#   ./scripts/run_exams.sh              # Run all normal exams (A-E)
#   ./scripts/run_exams.sh hard         # Run all hard exams (A_hard-E_hard)
#   ./scripts/run_exams.sh insane       # Run insane exams (Q-U)
#   ./scripts/run_exams.sh ultra        # Run ultra-hard exams (G-P)
#   ./scripts/run_exams.sh Q            # Run a specific exam
#   ./scripts/run_exams.sh Q R S        # Run specific exams

cd "$(dirname "$0")/.." || exit 1

MAX_ALGO=${MAX_ALGO:-20}
MAX_LLM=${MAX_LLM:-20}
LLM_URL=${LLM_URL:-http://localhost:11235}
TYPE=${TYPE:-infostealer}

case "${1:-normal}" in
    normal)  EXAMS="A B C D E" ;;
    hard)    EXAMS="A_hard B_hard C_hard D_hard E_hard" ;;
    ultra)   EXAMS="G G_hard H H_hard I I_hard J J_hard K K_hard L L_hard M M_hard N N_hard O O_hard P P_hard" ;;
    insane)  EXAMS="Q R S T U" ;;
    *)       EXAMS="$*" ;;
esac

echo "════════════════════════════════════════════════════════"
echo "  Evasion Exam Runner"
echo "  Exams: $EXAMS"
echo "  Budget: ${MAX_ALGO} algo + ${MAX_LLM} LLM per level"
echo "  LLM: $LLM_URL"
echo "════════════════════════════════════════════════════════"
echo ""

RESULTS=""
for EXAM in $EXAMS; do
    echo "Running exam $EXAM..."
    OUTPUT=$(python3 -u templates/chunks/test_evasion_loop.py \
        --exam "$EXAM" --type "$TYPE" \
        --max-algo "$MAX_ALGO" --max-llm "$MAX_LLM" \
        --llm-url "$LLM_URL" 2>&1)

    LEVEL=$(echo "$OUTPUT" | grep -oP 'Levels passed: \K\d+' | tail -1)
    RUNS=$(echo "$OUTPUT" | grep -oP 'Total runs: \K\d+' | tail -1)
    echo "$EXAM: L${LEVEL:-0}/20 (${RUNS:-?} runs)"
    RESULTS="${RESULTS}${EXAM}: L${LEVEL:-0}/20 (${RUNS:-?} runs)\n"
    echo ""
done

echo "════════════════════════════════════════════════════════"
echo "  RESULTS SUMMARY"
echo "════════════════════════════════════════════════════════"
echo -e "$RESULTS"
