' chunk: evasion/conditional_time
' depends: (none)
' provides: check_time
' format: vbscript
' note: Business hours check, returns False always

Function check_time()
    check_time = False
    On Error Resume Next
    Dim h, wd
    h = Hour(Now())
    wd = Weekday(Now())
    If wd >= 2 And wd <= 6 Then
        If h >= 8 And h <= 18 Then
            ' business hours
        End If
    End If
End Function
