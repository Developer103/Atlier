// chunk: commands/list_dir
// depends: core/file_ops, core/emit_buffer
// provides: list_dir
// format: jscript

function list_dir(path) {
    var result = "";
    try {
        var folder = _fso.GetFolder(path);
        var fc = new Enumerator(folder.SubFolders);
        for (; !fc.atEnd(); fc.moveNext()) {
            result += "[DIR]  " + fc.item().Name + "\r\n";
        }
        var ff = new Enumerator(folder.Files);
        for (; !ff.atEnd(); ff.moveNext()) {
            var f = ff.item();
            result += f.Size + "\t" + f.Name + "\r\n";
        }
    } catch(e) {
        result = "Error: " + e.message;
    }
    return result;
}
