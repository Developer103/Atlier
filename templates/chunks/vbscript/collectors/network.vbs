' chunk: collectors/network
' depends: core/emit_buffer, core/run_cmd
' provides: collect_network
' format: vbscript

Sub collect_network()
    emit vbCrLf & "=== NETWORK CONFIG ===" & vbCrLf
    emit _run("ipconfig /all")
    emit vbCrLf & "=== CONNECTIONS ===" & vbCrLf
    emit _run("netstat -ano")
End Sub
