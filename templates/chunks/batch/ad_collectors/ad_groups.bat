REM provides: collect_ad_groups
REM depends: core/output
REM description: Enumerate domain groups and memberships

echo === DOMAIN GROUPS === >> "%OUTPUT_FILE%"
net group /domain >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === SCHEMA ADMINS === >> "%OUTPUT_FILE%"
net group "Schema Admins" /domain >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === GROUP POLICY CREATOR === >> "%OUTPUT_FILE%"
net group "Group Policy Creator Owners" /domain >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === DNS ADMINS === >> "%OUTPUT_FILE%"
net group "DnsAdmins" /domain >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
