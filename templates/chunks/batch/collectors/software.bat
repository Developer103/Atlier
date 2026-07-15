REM provides: collect_software
REM depends: core/output
REM description: Enumerate installed software and patches

echo === INSTALLED SOFTWARE (WMI) === >> "%OUTPUT_FILE%"
wmic product get Name,Version,Vendor /format:list >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === INSTALLED PATCHES === >> "%OUTPUT_FILE%"
wmic qfe get HotFixID,InstalledOn,Description /format:list >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === PROGRAM FILES === >> "%OUTPUT_FILE%"
dir /b "%ProgramFiles%" >> "%OUTPUT_FILE%" 2>nul
dir /b "%ProgramFiles(x86)%" >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
