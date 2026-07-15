' chunk: ad_collectors/ad_users
' depends: core/emit_buffer, core/run_cmd
' provides: collect_ad_users
' format: vbscript

Sub collect_ad_users()
    emit vbCrLf & "=== AD USERS ===" & vbCrLf
    emit _run("net user /domain 2>NUL")
End Sub
