// chunk: ad_collectors/ad_computers
// depends: core/emit_buffer, core/run_cmd
// provides: collect_ad_computers
// format: jscript

function collect_ad_computers() {
    emit("\r\n=== AD COMPUTERS ===\r\n");
    emit(_run("net group \"Domain Computers\" /domain"));
}
