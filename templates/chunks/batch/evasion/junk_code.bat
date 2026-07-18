REM provides: evasion_junk_code
REM depends: (none)
REM description: Insert dead code blocks that change file hash without affecting execution

REM Dead code block 1: impossible condition
if "%COMPUTERNAME%"=="ZZZZNEVERMATCH_%RANDOM%" (
    set "J1=meaningless_value_1"
    set "J2=meaningless_value_2"
    wmic cpu get name >nul 2>nul
    reg query "HKLM\SOFTWARE\Microsoft" >nul 2>nul
    echo %J1%%J2% >nul
)

REM Dead code block 2: arithmetic that never matches
set /a "JUNK_MATH=42 * 17 + 9 - 3"
if "%JUNK_MATH%"=="99999" echo %JUNK_MATH% >nul

REM Dead code block 3: unreachable goto
if "%OS%"=="ZZZNEVER" goto :junk_label
goto :junk_skip
:junk_label
set "DEAD_VAR=this_never_runs_%RANDOM%"
hostname >nul 2>nul
:junk_skip
