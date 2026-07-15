REM provides: collect_scheduled_tasks
REM depends: core/output
REM description: Enumerate scheduled tasks for persistence and priv-esc info

echo === SCHEDULED TASKS === >> "%OUTPUT_FILE%"
schtasks /query /fo LIST /v >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
