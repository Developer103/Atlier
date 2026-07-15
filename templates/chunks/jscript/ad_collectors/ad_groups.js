// chunk: ad_collectors/ad_groups
// depends: core/emit_buffer, core/run_cmd
// provides: collect_ad_groups
// format: jscript

function collect_ad_groups() {
    emit("\r\n=== AD GROUPS ===\r\n");
    emit(_run("net group /domain"));
}
