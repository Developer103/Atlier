' chunk: ad_collectors/ad_domains
' depends: core/emit_buffer, core/run_cmd
' provides: collect_ad_domains
' format: vbscript

Sub collect_ad_domains()
    emit vbCrLf & "=== AD DOMAIN INFO ===" & vbCrLf
    emit "--- Domain Controllers ---" & vbCrLf
    emit _run("nltest /dclist: 2>NUL")
    emit "--- DC Discovery ---" & vbCrLf
    emit _run("nltest /dsgetdc: 2>NUL")
    emit "--- Workstation Config ---" & vbCrLf
    emit _run("net config workstation")
    emit "--- Domain Trusts ---" & vbCrLf
    emit _run("nltest /domain_trusts 2>NUL")
End Sub
