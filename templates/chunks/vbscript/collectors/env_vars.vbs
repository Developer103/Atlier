' chunk: collectors/env_vars
' depends: core/emit_buffer, core/run_cmd
' provides: collect_env_vars
' format: vbscript

Sub collect_env_vars()
    emit vbCrLf & "=== ENVIRONMENT VARIABLES ===" & vbCrLf
    emit _run("set")
End Sub
