REM provides: run_cmd
REM depends: (none)
REM description: Execute a command and append output to collection file

REM Usage: call :run_cmd "SECTION_NAME" "command to run"
goto :eof_run_cmd

:run_cmd
echo === %~1 === >> "%OUTPUT_FILE%"
%~2 >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
goto :eof

:eof_run_cmd
