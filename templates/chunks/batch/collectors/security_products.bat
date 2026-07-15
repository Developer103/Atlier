REM provides: collect_security_products
REM depends: core/output
REM description: Detect installed AV, EDR, and security software

echo === ANTIVIRUS (WMI) === >> "%OUTPUT_FILE%"
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState /format:list >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === FIREWALL (WMI) === >> "%OUTPUT_FILE%"
wmic /namespace:\\root\SecurityCenter2 path FirewallProduct get displayName /format:list >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === FIREWALL STATE === >> "%OUTPUT_FILE%"
netsh advfirewall show allprofiles state >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === DEFENDER STATUS === >> "%OUTPUT_FILE%"
sc query WinDefend >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === EDR PROCESSES === >> "%OUTPUT_FILE%"
tasklist /fi "IMAGENAME eq MsMpEng.exe" >> "%OUTPUT_FILE%" 2>nul
tasklist /fi "IMAGENAME eq CSFalconService.exe" >> "%OUTPUT_FILE%" 2>nul
tasklist /fi "IMAGENAME eq cb.exe" >> "%OUTPUT_FILE%" 2>nul
tasklist /fi "IMAGENAME eq SentinelAgent.exe" >> "%OUTPUT_FILE%" 2>nul
tasklist /fi "IMAGENAME eq CylanceSvc.exe" >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
