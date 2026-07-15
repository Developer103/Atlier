' chunk: collectors/drives
' depends: core/emit_buffer, core/file_ops
' provides: collect_drives
' format: vbscript

Sub collect_drives()
    emit vbCrLf & "=== DRIVES ===" & vbCrLf
    Dim d
    For Each d In _fso.Drives
        On Error Resume Next
        emit "  " & d.DriveLetter & ": " & d.DriveType & " "
        If d.IsReady Then
            emit d.FileSystem & " " & FormatNumber(d.FreeSpace / 1073741824, 1) & "/" & FormatNumber(d.TotalSize / 1073741824, 1) & " GB"
            If Len(d.VolumeName) > 0 Then emit " [" & d.VolumeName & "]"
        Else
            emit "(not ready)"
        End If
        emit vbCrLf
        On Error GoTo 0
    Next
End Sub
