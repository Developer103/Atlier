' chunk: evasion/gpu_check
' depends: core/run_cmd
' provides: check_gpu
' format: vbscript
' note: GPU name check via WMI, virtual adapters suggest VM

Function check_gpu()
    check_gpu = False
    On Error Resume Next
    Dim objWMI, colItems, objItem, gpuName
    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colItems = objWMI.ExecQuery("SELECT Name FROM Win32_VideoController")
    For Each objItem In colItems
        gpuName = LCase(objItem.Name)
        If InStr(gpuName, "basic display") > 0 Or _
           InStr(gpuName, "vmware") > 0 Or _
           InStr(gpuName, "virtualbox") > 0 Or _
           InStr(gpuName, "hyper-v") > 0 Then
            ' virtual GPU detected
        End If
    Next
End Function
