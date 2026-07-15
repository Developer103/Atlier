REM provides: collect_ad_users
REM depends: core/output
REM description: Enumerate domain users and account details

echo === DOMAIN USERS === >> "%OUTPUT_FILE%"
net user /domain >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === DOMAIN ADMINS === >> "%OUTPUT_FILE%"
net group "Domain Admins" /domain >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === ENTERPRISE ADMINS === >> "%OUTPUT_FILE%"
net group "Enterprise Admins" /domain >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === CURRENT DOMAIN === >> "%OUTPUT_FILE%"
echo %USERDOMAIN% >> "%OUTPUT_FILE%"
echo %USERDNSDOMAIN% >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
