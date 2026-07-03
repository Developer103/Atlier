#!/bin/bash
PORT=${1:-9001}
OUT="exfil_$(date +%Y%m%d_%H%M%S).bin"
echo "Listening on :$PORT → $OUT"
nc -l -p $PORT > "$OUT"
SIZE=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
echo "Received: $SIZE bytes → $OUT"
if [ "$SIZE" -gt 100 ]; then
    echo "Preview:"
    strings "$OUT" | head -20
fi
