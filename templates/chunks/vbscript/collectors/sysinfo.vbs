' chunk: collectors/sysinfo
' depends: core/emit_buffer, core/run_cmd
' provides: collect_sysinfo
' format: vbscript

Sub collect_sysinfo()
    emit "=== SYSTEM INFO ===" & vbCrLf
    emit "Hostname: " & _run("hostname")
    emit "User: " & _run("whoami")
    emit _run("systeminfo")
End Sub
