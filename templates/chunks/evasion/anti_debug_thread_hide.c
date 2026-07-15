// chunk: evasion/anti_debug_thread_hide
// depends: (none)
// provides: anti_debug_check
// headers: windows.h
// risk: low
// note: ThreadHideFromDebugger — makes the current thread invisible to debuggers. If a debugger is attached, it loses track of this thread.

#ifndef CHUNK_ANTI_DEBUG_THREAD_HIDE
#define CHUNK_ANTI_DEBUG_THREAD_HIDE

#include <windows.h>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define ThreadHideFromDebugger 0x11

typedef NTSTATUS (NTAPI *pfnNtSetInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

typedef NTSTATUS (NTAPI *pfnNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

static int anti_debug_check(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnNtSetInformationThread NtSIT = (pfnNtSetInformationThread)
        GetProcAddress(ntdll, "NtSetInformationThread");
    if (!NtSIT) return 0;

    // Hide the current thread from any attached debugger
    NTSTATUS status = NtSIT(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);

    // If STATUS_SUCCESS, the thread is now hidden
    // If a debugger WAS attached, it will silently lose events from this thread
    // We don't return 1 here because the point is evasion, not detection
    // But we can also do a basic IsDebuggerPresent check
    if (IsDebuggerPresent())
        return 1;

    // Check via PEB.BeingDebugged directly
    BOOL debugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
    if (debugged)
        return 1;

    return 0;
}

#endif
