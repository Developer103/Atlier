REM provides: collect_ad_computers
REM depends: core/output
REM description: Enumerate domain computers, DCs, and trust relationships

echo === DOMAIN CONTROLLERS === >> "%OUTPUT_FILE%"
nltest /dclist:%USERDOMAIN% >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === DOMAIN COMPUTERS === >> "%OUTPUT_FILE%"
net group "Domain Computers" /domain >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === TRUST RELATIONSHIPS === >> "%OUTPUT_FILE%"
nltest /domain_trusts >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === DOMAIN SID === >> "%OUTPUT_FILE%"
whoami /user >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === DSQUERY SERVERS === >> "%OUTPUT_FILE%"
dsquery server -o rdn >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
