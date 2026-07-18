' chunk: evasion/split_join
' depends: (none)
' provides: _d
' format: vbscript
' note: XOR decode with key 0x55

Function _d(arr)
    Dim s, i
    s = ""
    For i = 0 To UBound(arr)
        s = s & Chr(arr(i) Xor &H55)
    Next
    _d = s
End Function
