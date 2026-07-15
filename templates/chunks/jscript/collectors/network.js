// chunk: collectors/network
// depends: core/emit_buffer, core/run_cmd
// provides: collect_network
// format: jscript

function collect_network() {
    emit("\r\n=== NETWORK INFO ===\r\n");
    emit(_run("ipconfig /all"));
    emit("\r\n=== CONNECTIONS ===\r\n");
    emit(_run("netstat -ano"));
}
