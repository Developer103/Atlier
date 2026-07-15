' chunk: evasion/wmi_evasion
' depends: (none)
' provides: WMISandboxCheck
' format: vbscript
' note: Deep WMI-based sandbox/VM detection — queries hardware
'   identifiers, BIOS strings, MAC addresses for VM indicators.
'   Returns a score but never gates execution.

Function WMISandboxCheck()
    On Error Resume Next
    Dim wmi, score
    score = 0
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")

    ' Check Win32_ComputerSystem for VM model/manufacturer strings
    Dim csItems, cs
    Set csItems = wmi.ExecQuery("SELECT Model, Manufacturer, TotalPhysicalMemory, NumberOfLogicalProcessors FROM Win32_ComputerSystem")
    For Each cs In csItems
        Dim model, mfr
        model = LCase(cs.Model & "")
        mfr = LCase(cs.Manufacturer & "")
        Dim vmModels, vi
        vmModels = Array("vmware", "virtualbox", "virtual", "qemu", "kvm", "xen", "bochs", "parallels")
        For vi = 0 To UBound(vmModels)
            If InStr(model, vmModels(vi)) > 0 Or InStr(mfr, vmModels(vi)) > 0 Then score = score + 1
        Next
        ' Low RAM (< 2 GB) or low CPU (< 2) — common in sandboxes
        If CLng(cs.TotalPhysicalMemory) < 2147483648 Then score = score + 1
        If CInt(cs.NumberOfLogicalProcessors) < 2 Then score = score + 1
    Next

    ' Check Win32_BIOS for VM-specific serial/version strings
    Dim biosItems, bios
    Set biosItems = wmi.ExecQuery("SELECT SerialNumber, Version FROM Win32_BIOS")
    For Each bios In biosItems
        Dim serial, ver
        serial = LCase(bios.SerialNumber & "")
        ver = LCase(bios.Version & "")
        Dim vmBios, bi
        vmBios = Array("vmware", "vbox", "qemu", "virtual", "parallels", "bochs", "xen")
        For bi = 0 To UBound(vmBios)
            If InStr(serial, vmBios(bi)) > 0 Or InStr(ver, vmBios(bi)) > 0 Then score = score + 1
        Next
    Next

    ' Check Win32_BaseBoard.Manufacturer for non-physical hardware
    Dim bbItems, bb
    Set bbItems = wmi.ExecQuery("SELECT Manufacturer, Product FROM Win32_BaseBoard")
    For Each bb In bbItems
        Dim bbMfr
        bbMfr = LCase(bb.Manufacturer & "")
        If InStr(bbMfr, "intel") = 0 And InStr(bbMfr, "asus") = 0 And _
           InStr(bbMfr, "gigabyte") = 0 And InStr(bbMfr, "msi") = 0 And _
           InStr(bbMfr, "dell") = 0 And InStr(bbMfr, "hp") = 0 And _
           InStr(bbMfr, "lenovo") = 0 And InStr(bbMfr, "acer") = 0 Then
            score = score + 1
        End If
    Next

    ' Check Win32_DiskDrive for VM disk identifiers
    Dim diskItems, disk
    Set diskItems = wmi.ExecQuery("SELECT Model, Size FROM Win32_DiskDrive")
    For Each disk In diskItems
        Dim diskModel
        diskModel = LCase(disk.Model & "")
        Dim vmDisks, di
        vmDisks = Array("vbox", "vmware", "virtual", "qemu")
        For di = 0 To UBound(vmDisks)
            If InStr(diskModel, vmDisks(di)) > 0 Then score = score + 1
        Next
        ' Very small disk (< 60 GB)
        If CDbl(disk.Size) < 64424509440 Then score = score + 1
    Next

    ' Check Win32_NetworkAdapter MAC addresses for VM OUI prefixes
    Dim netItems, net
    Set netItems = wmi.ExecQuery("SELECT MACAddress FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL")
    Dim vmMacs, mi
    vmMacs = Array("00:0C:29", "00:50:56", "08:00:27", "52:54:00", "00:1C:42", "00:16:3E", "00:15:5D")
    For Each net In netItems
        Dim mac
        mac = LCase(net.MACAddress & "")
        For mi = 0 To UBound(vmMacs)
            If Left(mac, Len(LCase(vmMacs(mi)))) = LCase(vmMacs(mi)) Then score = score + 1
        Next
    Next

    WMISandboxCheck = 0
    On Error GoTo 0
End Function
