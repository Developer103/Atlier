' chunk: evasion/installed_software
' depends: core/run_cmd
' provides: check_software
' format: vbscript
' note: Installed software count check, few programs suggests sandbox

Function check_software()
    check_software = False
    On Error Resume Next
    Dim result, lines
    result = _run("wmic product get name /format:csv")
    lines = Split(result, vbCrLf)
    Dim count, i
    count = 0
    For i = 0 To UBound(lines)
        If Len(Trim(lines(i))) > 2 Then
            count = count + 1
        End If
    Next
    If count < 10 Then
        ' very few programs installed
    End If
End Function
