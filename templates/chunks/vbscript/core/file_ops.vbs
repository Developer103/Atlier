' chunk: core/file_ops
' depends: (none)
' provides: _fso, file_exists_f, read_file, grab_file
' format: vbscript

Dim _fso
Set _fso = CreateObject("Scripting.FileSystemObject")

Function file_exists_f(p)
    file_exists_f = _fso.FileExists(p)
End Function

Function read_file(p, maxBytes)
    On Error Resume Next
    Dim f, txt
    read_file = ""
    If Not _fso.FileExists(p) Then Exit Function
    Set f = _fso.OpenTextFile(p, 1)
    txt = f.ReadAll()
    f.Close
    If maxBytes > 0 And Len(txt) > maxBytes Then
        txt = Left(txt, maxBytes)
    End If
    read_file = txt
    On Error GoTo 0
End Function

Function grab_file(src, tag)
    On Error Resume Next
    Dim tmp, txt
    grab_file = ""
    tmp = _s.ExpandEnvironmentStrings("%TEMP%") & "\" & tag & ".tmp"
    _fso.CopyFile src, tmp, True
    txt = read_file(tmp, 1048576)
    _fso.DeleteFile tmp
    grab_file = txt
    On Error GoTo 0
End Function
