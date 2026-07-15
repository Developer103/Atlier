' chunk: collectors/installed_software
' depends: core/emit_buffer, core/run_cmd
' provides: collect_installed_software
' format: vbscript

Sub collect_installed_software()
    emit vbCrLf & "=== INSTALLED SOFTWARE ===" & vbCrLf
    emit _run("wmic product get name,version /format:csv 2>NUL")
End Sub
