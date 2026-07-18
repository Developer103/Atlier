' chunk: evasion/process_shell_app
' depends: (none)
' provides: create_process
' format: vbscript
' note: Process creation via Shell.Application ShellExecute

Sub create_process(cmd)
    On Error Resume Next
    Dim app
    Set app = CreateObject("Shell.Application")
    app.ShellExecute "cmd.exe", "/c " & cmd, "", "", 0
End Sub
