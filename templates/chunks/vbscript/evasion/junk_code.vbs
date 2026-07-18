' chunk: evasion/junk_code
' depends: (none)
' provides: junk_init
' format: vbscript
' note: Dead code branches for static analysis confusion

Sub junk_init()
    On Error Resume Next
    Dim jA, jB, jC, jD, jE, jF
    jA = 3735928559.0
    jB = Sin(jA) * Cos(jA)
    jC = Hex(CLng(jA And &HFFFF&))
    If jB > 9999 Then
        Dim jObj
        Set jObj = CreateObject("Scripting.Dictionary")
        jObj.Add "x", jC
        jD = jObj.Item("x")
        Set jObj = Nothing
    End If
    jE = StrReverse(String(16, "A"))
    jF = Len(jE) Xor Len(jC)
    Dim jArr(4)
    jArr(0) = jA : jArr(1) = jB
    jArr(2) = Asc("Z") : jArr(3) = Timer
    jArr(4) = Int(Rnd * 65535)
    Dim jG
    jG = Join(Array(jC, jE, CStr(jF)), "-")
    If InStr(jG, "ZZZZ") > 0 Then
        jA = Log(1)
    End If
End Sub
