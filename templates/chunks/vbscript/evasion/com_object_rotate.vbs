' chunk: evasion/com_object_rotate
' depends: (none)
' provides: create_com
' format: vbscript
' note: Rotate COM object creation method for behavioral diversity

Function create_com(progId)
    On Error Resume Next
    Dim obj, method
    Randomize
    method = Int(Rnd * 3)
    Select Case method
        Case 0
            Set obj = CreateObject(progId)
        Case 1
            Set obj = GetObject("new:" & progId)
        Case 2
            Set obj = WScript.CreateObject(progId)
    End Select
    If Err.Number <> 0 Then
        Err.Clear
        Set obj = CreateObject(progId)
    End If
    Set create_com = obj
End Function
