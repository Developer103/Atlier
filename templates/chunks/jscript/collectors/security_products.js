// chunk: collectors/security_products
// depends: core/emit_buffer, core/run_cmd
// provides: collect_security_products
// format: jscript

function collect_security_products() {
    emit("\r\n=== SECURITY PRODUCTS ===\r\n");
    emit(_run("wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState /format:csv 2>NUL"));
    emit(_run("wmic /namespace:\\\\root\\SecurityCenter2 path FirewallProduct get displayName,productState /format:csv 2>NUL"));
    emit("\r\n=== EDR PROCESSES ===\r\n");
    emit(_run("tasklist /fi \"IMAGENAME eq CSFalconService.exe\" /fo csv /nh 2>NUL"));
    emit(_run("tasklist /fi \"IMAGENAME eq MsSense.exe\" /fo csv /nh 2>NUL"));
    emit(_run("tasklist /fi \"IMAGENAME eq elastic-agent.exe\" /fo csv /nh 2>NUL"));
    emit(_run("tasklist /fi \"IMAGENAME eq SentinelAgent.exe\" /fo csv /nh 2>NUL"));
    emit(_run("tasklist /fi \"IMAGENAME eq CbDefense.exe\" /fo csv /nh 2>NUL"));
}
