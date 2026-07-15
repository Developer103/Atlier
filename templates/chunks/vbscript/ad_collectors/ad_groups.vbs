' chunk: ad_collectors/ad_groups
' depends: core/emit_buffer, core/run_cmd
' provides: collect_ad_groups
' format: vbscript

Sub collect_ad_groups()
    emit vbCrLf & "=== AD GROUPS ===" & vbCrLf
    emit _run("net group /domain 2>NUL")
End Sub
