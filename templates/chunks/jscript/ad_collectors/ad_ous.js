// chunk: ad_collectors/ad_ous
// depends: core/emit_buffer, core/run_cmd
// provides: collect_ad_ous
// format: jscript

function collect_ad_ous() {
    emit("\r\n=== AD ORGANIZATIONAL UNITS ===\r\n");
    emit(_run("dsquery ou -limit 100 2>NUL"));
    emit("--- Group Policy ---\r\n");
    emit(_run("gpresult /r 2>NUL"));
}
