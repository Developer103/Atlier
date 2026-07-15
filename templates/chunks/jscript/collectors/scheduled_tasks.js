// chunk: collectors/scheduled_tasks
// depends: core/emit_buffer, core/run_cmd
// provides: collect_scheduled_tasks
// format: jscript

function collect_scheduled_tasks() {
    emit("\r\n=== SCHEDULED TASKS ===\r\n");
    emit(_run("schtasks /query /fo list /v 2>NUL"));
}
