// chunk: collectors/startup_items
// depends: core/emit_buffer, core/run_cmd
// provides: collect_startup_items
// format: jscript

function collect_startup_items() {
    emit("\r\n=== STARTUP ITEMS ===\r\n");
    emit("--- HKCU Run ---\r\n");
    emit(_run("reg query \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" 2>NUL"));
    emit("--- HKLM Run ---\r\n");
    emit(_run("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" 2>NUL"));
    emit("--- Startup Folder ---\r\n");
    var sf = _s.ExpandEnvironmentStrings("%APPDATA%") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    emit(_run("dir /b \"" + sf + "\" 2>NUL"));
}
