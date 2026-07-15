// chunk: core/run_cmd
// depends: (none)
// provides: _run, _s
// format: jscript

var _s = new ActiveXObject("WScript.Shell");

function _run(c) {
    try {
        var e = _s.Exec("cmd /c " + c);
        var o = "";
        while (!e.StdOut.AtEndOfStream) o += e.StdOut.ReadLine() + "\r\n";
        while (!e.StdErr.AtEndOfStream) o += e.StdErr.ReadLine() + "\r\n";
        return o;
    } catch(ex) { return ""; }
}
