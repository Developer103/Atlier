' chunk: evasion/string_obfusc
' depends: (none)
' provides: _d
' format: vbscript

Function _d(arr)
    Dim s, i
    s = ""
    For i = 0 To UBound(arr)
        s = s & Chr(arr(i))
    Next
    _d = s
End Function
