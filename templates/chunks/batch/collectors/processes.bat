REM provides: collect_processes
REM depends: core/output
REM description: Enumerate running processes and services

echo === RUNNING PROCESSES === >> "%OUTPUT_FILE%"
tasklist /v >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === SERVICES === >> "%OUTPUT_FILE%"
sc query state= all >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === WMI PROCESS LIST === >> "%OUTPUT_FILE%"
wmic process get Name,ProcessId,CommandLine /format:list >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
