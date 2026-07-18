' chunk: evasion/encoding_rotate
' depends: (none)
' provides: _d
' format: vbscript
' note: Multi-encoding decode supporting charcode, hex, XOR by prefix

Function _d(arr)
    Dim s, i, prefix
    s = ""
    If UBound(arr) < 0 Then _d = s : Exit Function
    prefix = arr(0)
    Select Case prefix
        Case 1 ' charcode
            For i = 1 To UBound(arr) : s = s & Chr(arr(i)) : Next
        Case 2 ' hex
            For i = 1 To UBound(arr)
                s = s & Chr(CInt("&H" & CStr(arr(i))))
            Next
        Case 3 ' XOR with key in arr(1)
            Dim k : k = arr(1)
            For i = 2 To UBound(arr) : s = s & Chr(arr(i) Xor k) : Next
        Case Else ' plain charcode fallback
            For i = 0 To UBound(arr) : s = s & Chr(arr(i)) : Next
    End Select
    _d = s
End Function
