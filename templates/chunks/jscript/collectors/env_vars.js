// chunk: collectors/env_vars
// depends: core/emit_buffer, core/run_cmd
// provides: collect_env_vars
// format: jscript

function collect_env_vars() {
    emit("\r\n=== ENVIRONMENT VARIABLES ===\r\n");
    emit(_run("set"));
}
