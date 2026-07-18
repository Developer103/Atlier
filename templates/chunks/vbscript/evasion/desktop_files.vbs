' chunk: evasion/desktop_files
' depends: core/run_cmd
' provides: check_desktop
' format: vbscript
' note: Desktop file count check, empty desktop suggests sandbox

Function check_desktop()
    check_desktop = False
    On Error Resume Next
    Dim sh, desktop, fso, folder
    Set sh = CreateObject("WScript.Shell")
    desktop = sh.SpecialFolders("Desktop")
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set folder = fso.GetFolder(desktop)
    If folder.Files.Count = 0 Then
        ' empty desktop
    End If
End Function
