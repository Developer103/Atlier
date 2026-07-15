' chunk: collectors/startup_items
' depends: core/emit_buffer, core/run_cmd
' provides: collect_startup_items
' format: vbscript

Sub collect_startup_items()
    emit vbCrLf & "=== STARTUP ITEMS ===" & vbCrLf
    emit "--- HKCU Run ---" & vbCrLf
    emit _run("reg query ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"" 2>NUL")
    emit "--- HKLM Run ---" & vbCrLf
    emit _run("reg query ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"" 2>NUL")
    emit "--- Startup Folder ---" & vbCrLf
    Dim sf
    sf = _sh.ExpandEnvironmentStrings("%APPDATA%") & "\Microsoft\Windows\Start Menu\Programs\Startup"
    emit _run("dir /b """ & sf & """ 2>NUL")
End Sub
