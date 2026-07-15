' chunk: collectors/processes
' depends: core/emit_buffer, core/run_cmd
' provides: collect_processes
' format: vbscript

Sub collect_processes()
    emit vbCrLf & "=== RUNNING PROCESSES ===" & vbCrLf
    emit _run("tasklist /fo csv /nh")
End Sub
