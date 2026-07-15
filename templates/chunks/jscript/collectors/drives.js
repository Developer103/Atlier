// chunk: collectors/drives
// depends: core/emit_buffer, core/file_ops
// provides: collect_drives
// format: jscript

function collect_drives() {
    emit("\r\n=== DRIVES ===\r\n");
    var drives = new Enumerator(_fso.Drives);
    for (; !drives.atEnd(); drives.moveNext()) {
        var d = drives.item();
        var info = d.DriveLetter + ": " + d.DriveType;
        if (d.IsReady) {
            info += " | " + d.FileSystem + " | " + Math.round(d.FreeSpace/1073741824) + "GB free / " + Math.round(d.TotalSize/1073741824) + "GB total";
            if (d.VolumeName) info += " | " + d.VolumeName;
        }
        emit("  " + info + "\r\n");
    }
}
