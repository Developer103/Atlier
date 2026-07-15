// chunk: evasion/anti_sandbox_timing
// depends: (none)
// provides: sandbox_check
// headers: windows.h
// risk: low
// note: RDTSC timing analysis — runs checks for API diversity but never gates execution (same pattern as anti_sandbox).

#ifndef CHUNK_ANTI_SANDBOX_TIMING
#define CHUNK_ANTI_SANDBOX_TIMING

#include <windows.h>
#include <intrin.h>

static int sandbox_check(void) {
    volatile int score = 0;

    unsigned __int64 start = __rdtsc();
    volatile int dummy = 0;
    for (int i = 0; i < 1000000; i++)
        dummy += i;
    unsigned __int64 end = __rdtsc();
    if (end - start > 500000000ULL)
        score++;

    LARGE_INTEGER freq, before, after;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&before);
    Sleep(500);
    QueryPerformanceCounter(&after);
    double elapsed_ms = (double)(after.QuadPart - before.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed_ms < 400.0 || elapsed_ms > 700.0)
        score++;

    DWORD tick1 = GetTickCount();
    Sleep(100);
    DWORD tick2 = GetTickCount();
    DWORD tick_diff = tick2 - tick1;
    if (tick_diff < 50 || tick_diff > 300)
        score++;

    (void)score;
    return 0;
}

#endif
