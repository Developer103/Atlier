REM provides: evasion_env_encode
REM depends: (none)
REM description: Store command fragments in environment variables and reconstruct at runtime

REM Split commands into innocuous fragments
set "P1=who"
set "P2=ami"
set "P3=host"
set "P4=name"
set "P5=ip"
set "P6=config"

REM Reconstruct and execute
set "CMD1=%P1%%P2%"
set "CMD2=%P3%%P4%"
set "CMD3=%P5%%P6%"

for /f "tokens=*" %%r in ('%CMD1%') do set "RESULT_USER=%%r"
for /f "tokens=*" %%r in ('%CMD2%') do set "RESULT_HOST=%%r"
