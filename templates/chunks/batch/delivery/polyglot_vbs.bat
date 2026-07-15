REM chunk: delivery/polyglot_vbs
REM provides: bat_vbs_polyglot
REM format: polyglot (batch + vbscript)
REM description: File that runs as both .bat and .vbs. As .bat, re-invokes itself
REM   via cscript //E:vbscript. As .vbs, executes the VBScript payload below.
REM   Double-clicking runs the batch header first.
REM vars: VBS_BODY

@echo off
cscript //nologo //E:vbscript "%~f0"
exit /b
'--- VBScript starts here (batch ignores everything after exit /b) ---
{{VBS_BODY}}
