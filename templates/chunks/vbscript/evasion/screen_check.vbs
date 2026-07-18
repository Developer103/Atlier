' chunk: evasion/screen_check
' depends: core/run_cmd
' provides: check_screen
' format: vbscript
' note: WMI screen resolution check, low res suggests sandbox

Function check_screen()
    check_screen = False
    On Error Resume Next
    Dim objWMI, colItems, objItem
    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colItems = objWMI.ExecQuery("SELECT CurrentHorizontalResolution FROM Win32_VideoController")
    For Each objItem In colItems
        If objItem.CurrentHorizontalResolution < 1280 Then
            ' low resolution detected
        End If
    Next
End Function
