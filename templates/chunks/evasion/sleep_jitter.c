// chunk: evasion/sleep_jitter
// depends: (none)
// provides: jitter_sleep
// note: randomized sleep to break behavioral patterns

#ifndef JITTER_SLEEP_DEFINED
#define JITTER_SLEEP_DEFINED

#include <windows.h>

static void jitter_sleep(DWORD min_ms, DWORD max_ms) {
    DWORD range = max_ms - min_ms;
    DWORD wait = min_ms + (GetTickCount() % (range + 1));
    Sleep(wait);
}

#endif
