// chunk: evasion/deferred_exec
// depends: (none)
// provides: deferred_wait
// headers: windows.h
// risk: medium
// note: Random startup delay to defeat sandbox auto-analysis timeouts
// vars: DEFERRED_BASE_MS (default 10000), DEFERRED_RANGE_MS (default 50000)

#ifndef CHUNK_DEFERRED_EXEC
#define CHUNK_DEFERRED_EXEC

#ifndef DEFERRED_BASE_MS
#define DEFERRED_BASE_MS 10000
#endif
#ifndef DEFERRED_RANGE_MS
#define DEFERRED_RANGE_MS 50000
#endif

static void deferred_wait(void) {
    DWORD wait = DEFERRED_BASE_MS + (GetTickCount() % DEFERRED_RANGE_MS);
    DWORD chunk = 5000;
    while (wait > 0) {
        DWORD s = (wait > chunk) ? chunk : wait;
        Sleep(s);
        wait -= s;
    }
}

#endif
