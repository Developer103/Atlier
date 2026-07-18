REM provides: evasion_delayed_expand
REM depends: (none)
REM description: Use delayed expansion for runtime string construction invisible to static analysis

setlocal EnableDelayedExpansion

REM Build command strings character by character
set "A=w" & set "B=h" & set "C=o" & set "D=a" & set "E=m" & set "F=i"
set "CMD1=!A!!B!!C!!D!!E!!F!"

set "G=h" & set "H=o" & set "I=s" & set "J=t" & set "K=n" & set "L=a" & set "M=m" & set "N=e"
set "CMD2=!G!!H!!I!!J!!K!!L!!M!!N!"

REM Execute constructed commands
for /f "tokens=*" %%r in ('!CMD1!') do set "RESULT_USER=%%r"
for /f "tokens=*" %%r in ('!CMD2!') do set "RESULT_HOST=%%r"

endlocal
