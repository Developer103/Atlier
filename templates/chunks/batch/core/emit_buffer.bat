@REM chunk: core/emit_buffer
@REM depends: (none)
@REM provides: emit
@REM format: batch

set "_buf="
goto :emit_end
:emit
set "_buf=%_buf%%~1"
echo %~1
goto :eof
:emit_end
