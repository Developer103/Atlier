REM provides: evasion_delay
REM depends: (none)
REM description: Sleep before execution to evade sandbox time-based analysis

REM Default delay: 60 seconds (most sandboxes timeout at 30-60s)
if not defined DELAY_SECONDS set "DELAY_SECONDS=60"

REM Use ping -n for delay (works on all Windows versions, no timeout.exe needed)
ping -n %DELAY_SECONDS% 127.0.0.1 >nul 2>nul
