REM provides: collect_users
REM depends: core/output
REM description: Enumerate local users, groups, and privilege info

echo === LOCAL USERS === >> "%OUTPUT_FILE%"
net user >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === LOCAL GROUPS === >> "%OUTPUT_FILE%"
net localgroup >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === ADMINISTRATORS === >> "%OUTPUT_FILE%"
net localgroup Administrators >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === CURRENT PRIVILEGES === >> "%OUTPUT_FILE%"
whoami /priv >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === LOGON SESSIONS === >> "%OUTPUT_FILE%"
query user >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
