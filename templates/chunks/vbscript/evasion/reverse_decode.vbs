' chunk: evasion/reverse_decode
' depends: (none)
' provides: _d
' format: vbscript
' note: Decode reversed charcode array

Function _d(arr)
    Dim s, i
    s = ""
    For i = UBound(arr) To 0 Step -1
        s = s & Chr(arr(i))
    Next
    _d = s
End Function
