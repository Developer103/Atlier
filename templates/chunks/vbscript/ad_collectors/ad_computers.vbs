' chunk: ad_collectors/ad_computers
' depends: core/emit_buffer, core/run_cmd
' provides: collect_ad_computers
' format: vbscript

Sub collect_ad_computers()
    emit vbCrLf & "=== AD COMPUTERS ===" & vbCrLf
    emit _run("net group ""Domain Computers"" /domain 2>NUL")
End Sub
