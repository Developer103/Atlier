// chunk: evasion/behavioral_pacing
// depends: (none)
// provides: pace, decoy_work, g_sink
// headers: windows.h
// risk: none

#ifndef CHUNK_BEHAVIORAL_PACING
#define CHUNK_BEHAVIORAL_PACING

static volatile DWORD g_sink = 0;

static void pace(DWORD base_ms, DWORD jitter_ms) {
    DWORD actual = base_ms + (GetTickCount() % (jitter_ms + 1));
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    for (;;) {
        QueryPerformanceCounter(&t1);
        if ((DWORD)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart) >= actual) break;
        SwitchToThread();
    }
}

static void decoy_work(void) {
    POINT pt; GetCursorPos(&pt);
    g_sink += pt.x + pt.y;
    HWND dw = GetDesktopWindow();
    RECT rc; GetWindowRect(dw, &rc);
    g_sink += rc.right + rc.bottom;
    g_sink += GetTickCount();
}

#endif
