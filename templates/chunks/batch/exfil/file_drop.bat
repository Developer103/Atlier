REM provides: exfil_file_drop
REM depends: core/output
REM description: Copy output to a network share or local staging path

if not defined DROP_PATH set "DROP_PATH=%USERPROFILE%\Documents"
set "DROP_FILE=%DROP_PATH%\report_%COMPUTERNAME%_%RANDOM%.txt"

copy /y "%OUTPUT_FILE%" "%DROP_FILE%" >nul 2>nul
