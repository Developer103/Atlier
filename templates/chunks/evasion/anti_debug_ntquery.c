// chunk: evasion/anti_debug_ntquery
// depends: (none)
// provides: check_debugger
// headers: windows.h
// risk: low
// note: NtQueryInformationProcess with ProcessDebugPort (class 7), ProcessDebugFlags (class 31), and ProcessDebugObjectHandle (class 30). Three independent checks — any one returning positive means a debugger is attached. Lower detection risk than IsDebuggerPresent because it uses ntdll directly.

#ifndef CHUNK_ANTI_DEBUG_NTQUERY
#define CHUNK_ANTI_DEBUG_NTQUERY

#include <windows.h>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

static int check_debugger(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnNtQueryInformationProcess NtQIP = (pfnNtQueryInformationProcess)
        GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQIP) return 0;

    HANDLE hProc = GetCurrentProcess();

    // ProcessDebugPort (0x07) — non-zero if a debugger is attached
    DWORD_PTR debug_port = 0;
    NTSTATUS status = NtQIP(hProc, 7, &debug_port, sizeof(debug_port), NULL);
    if (status == STATUS_SUCCESS && debug_port != 0)
        return 1;

    // ProcessDebugFlags (0x1F) — returns 0 if debugger attached (inverted logic)
    DWORD debug_flags = 1;
    status = NtQIP(hProc, 0x1F, &debug_flags, sizeof(debug_flags), NULL);
    if (status == STATUS_SUCCESS && debug_flags == 0)
        return 1;

    // ProcessDebugObjectHandle (0x1E) — if a debug object handle exists,
    // a debugger created it. STATUS_SUCCESS + non-NULL = debugger present.
    HANDLE debug_obj = NULL;
    status = NtQIP(hProc, 0x1E, &debug_obj, sizeof(debug_obj), NULL);
    if (status == STATUS_SUCCESS)
        return 1;

    return 0;
}

#endif
