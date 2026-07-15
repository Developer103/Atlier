// chunk: ad_collectors/ad_domains
// depends: core/emit_buffer, core/run_cmd
// provides: collect_ad_domains
// format: jscript

function collect_ad_domains() {
    emit("\r\n=== AD DOMAIN INFO ===\r\n");
    emit("--- Domain Controllers ---\r\n");
    emit(_run("nltest /dclist: 2>NUL"));
    emit("--- DC Discovery ---\r\n");
    emit(_run("nltest /dsgetdc: 2>NUL"));
    emit("--- Workstation Config ---\r\n");
    emit(_run("net config workstation"));
    emit("--- Domain Trusts ---\r\n");
    emit(_run("nltest /domain_trusts 2>NUL"));
}
