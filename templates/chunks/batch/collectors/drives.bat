REM provides: collect_drives
REM depends: core/output
REM description: Enumerate disk drives and filesystem information

echo === LOGICAL DISKS === >> "%OUTPUT_FILE%"
wmic logicaldisk get Caption,Description,FileSystem,FreeSpace,Size /format:list >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === MAPPED DRIVES === >> "%OUTPUT_FILE%"
net use >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === DISK VOLUMES === >> "%OUTPUT_FILE%"
fsutil fsinfo drives >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
