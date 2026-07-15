REM provides: collect_sysinfo
REM depends: core/output
REM description: Collect system information via LOLBins

echo === SYSTEM INFO === >> "%OUTPUT_FILE%"
systeminfo >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === HOSTNAME === >> "%OUTPUT_FILE%"
hostname >> "%OUTPUT_FILE%"
echo. >> "%OUTPUT_FILE%"
echo === WHOAMI === >> "%OUTPUT_FILE%"
whoami /all >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === ENVIRONMENT === >> "%OUTPUT_FILE%"
set >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
