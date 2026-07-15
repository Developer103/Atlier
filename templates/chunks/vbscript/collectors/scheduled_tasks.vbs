' chunk: collectors/scheduled_tasks
' depends: core/emit_buffer, core/run_cmd
' provides: collect_scheduled_tasks
' format: vbscript

Sub collect_scheduled_tasks()
    emit vbCrLf & "=== SCHEDULED TASKS ===" & vbCrLf
    emit _run("schtasks /query /fo list /v 2>NUL")
End Sub
