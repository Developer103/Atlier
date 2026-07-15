// chunk: collectors/sysinfo
// depends: core/emit_buffer, core/run_cmd
// provides: collect_sysinfo
// format: jscript

function collect_sysinfo() {
    emit("=== SYSTEM INFO ===\r\n");
    emit("Hostname: " + _run("hostname"));
    emit("User: " + _run("whoami"));
    emit(_run("systeminfo"));
}
