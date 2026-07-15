' chunk: collectors/security_products
' depends: core/emit_buffer, core/run_cmd
' provides: collect_security_products
' format: vbscript

Sub collect_security_products()
    emit vbCrLf & "=== SECURITY PRODUCTS ===" & vbCrLf
    emit _run("wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState /format:csv 2>NUL")
    emit _run("wmic /namespace:\\root\SecurityCenter2 path FirewallProduct get displayName,productState /format:csv 2>NUL")
    emit vbCrLf & "=== EDR PROCESSES ===" & vbCrLf
    Dim edrProcs, i
    edrProcs = Array("CSFalconService.exe", "MsSense.exe", "elastic-agent.exe", "SentinelAgent.exe", "CbDefense.exe")
    For i = 0 To UBound(edrProcs)
        emit _run("tasklist /fi ""IMAGENAME eq " & edrProcs(i) & """ /fo csv /nh 2>NUL")
    Next
End Sub
