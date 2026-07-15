// chunk: collectors/installed_software
// depends: core/emit_buffer, core/run_cmd
// provides: collect_installed_software
// format: jscript

function collect_installed_software() {
    emit("\r\n=== INSTALLED SOFTWARE ===\r\n");
    emit(_run("wmic product get name,version /format:csv 2>NUL"));
    emit("\r\n=== PROGRAMS (REGISTRY) ===\r\n");
    emit(_run("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s /v DisplayName 2>NUL"));
}
