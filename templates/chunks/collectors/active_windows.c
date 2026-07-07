// chunk: collectors/active_windows
// depends: core/emit_buffer
// provides: collect_active_windows
// note: enumerate visible window titles — USER32 only, no new DLL

#ifndef CHUNK_ACTIVE_WINDOWS
#define CHUNK_ACTIVE_WINDOWS

static int g_aw_count;

static BOOL CALLBACK enum_windows_cb(HWND hwnd, LPARAM lParam) {
    (void)lParam;
    if (!IsWindowVisible(hwnd)) return TRUE;
    char title[256] = {0};
    int len = GetWindowTextA(hwnd, title, sizeof(title));
    if (len > 0 && title[0]) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        emitf("  [%5lu] %s\r\n", pid, title);
        g_aw_count++;
    }
    return TRUE;
}

static void collect_active_windows(void) {
    emitf("=== ACTIVE WINDOWS ===\r\n");
    g_aw_count = 0;
    EnumWindows(enum_windows_cb, 0);
    emitf("Total: %d visible windows\r\n\r\n", g_aw_count);
}

#endif
