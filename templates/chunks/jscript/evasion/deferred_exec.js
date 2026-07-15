// chunk: evasion/deferred_exec
// depends: (none)
// provides: deferred_wait
// format: jscript

function deferred_wait() {
    var delay = 5000 + Math.floor(Math.random() * 25000);
    WScript.Sleep(delay);
}
