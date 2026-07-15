' chunk: core/run_cmd
' depends: (none)
' provides: _run, _s
' format: vbscript

Dim _s
Set _s = CreateObject("WScript.Shell")

Function _run(c)
    On Error Resume Next
    Dim e, o
    Set e = _s.Exec("cmd /c " & c)
    o = ""
    Do While Not e.StdOut.AtEndOfStream
        o = o & e.StdOut.ReadLine() & vbCrLf
    Loop
    Do While Not e.StdErr.AtEndOfStream
        o = o & e.StdErr.ReadLine() & vbCrLf
    Loop
    _run = o
    On Error GoTo 0
End Function
