REM provides: init_output
REM depends: (none)
REM description: Initialize output file and helper macros

if not defined OUTPUT_FILE set "OUTPUT_FILE=%TEMP%\svc_%RANDOM%.tmp"
if exist "%OUTPUT_FILE%" del /f /q "%OUTPUT_FILE%" >nul 2>nul
echo. > "%OUTPUT_FILE%"
